/* 
 * FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 * Copyright (C) 2005-2012, Anthony Minessale II <anthm@freeswitch.org>
 *
 * Version: MPL 1.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 *
 * The Initial Developer of the Original Code is
 * Anthony Minessale II <anthm@freeswitch.org>
 * Portions created by the Initial Developer are Copyright (C)
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 * 
 * Anthony Minessale II <anthm@freeswitch.org>
 * Rupa Schomaker <rupa@rupa.com>
 * John Wehle <john@feith.com>
 *
 * Modified for Ogg support by Calvin Walton <calvin.walton@kepstin.ca>
 *
 * mod_oggshout.c -- Icecast Module for Ogg formats
 *
 * example filename: oggshout://user:pass@host.com/mount.opus (Opus audio)
 *                   oggshout://user:pass@host.com/mount.ogg  (Vorbis audio)
 *
 */

#include <switch.h>
#include <opus.h>
#include <vorbis/vorbisenc.h>
#include <vorbis/codec.h>
#include <shout/shout.h>

SWITCH_MODULE_LOAD_FUNCTION(mod_oggshout_load);
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_oggshout_shutdown);
SWITCH_MODULE_DEFINITION(mod_oggshout, mod_oggshout_load, mod_oggshout_shutdown, NULL);

static char *supported_formats[SWITCH_MAX_CODECS] = { 0 };

enum {
	OGGSHOUT_MODE_QUALITY = 1,
	OGGSHOUT_MODE_VBR,
	OGGSHOUT_MODE_MANAGED,
};

enum {
	OGGSHOUT_CODEC_VORBIS = 1,
	OGGSHOUT_CODEC_OPUS,
};

#define OGGSHOUT_DEFAULT_BITRATE 32000

static struct {
	uint32_t vorbis_mode;
	float    vorbis_quality;
	long     vorbis_bitrate;
	long     vorbis_max_bitrate;
	long     vorbis_min_bitrate;

	uint32_t opus_mode;
	int      opus_application;
	uint32_t opus_bitrate;
} globals;

struct oggshout_context {
	int codec;
	void *codec_priv;
	shout_t *shout;

	uint8_t thread_init;
	uint8_t encoder_ready;

	char *stream_url;
	switch_mutex_t *audio_mutex;
	switch_buffer_t *audio_buffer;
	switch_memory_pool_t *memory_pool;
	switch_file_handle_t *handle;
	int err;
	int mp3err;
	int dlen;
	size_t samplerate;
	uint8_t thread_running;
	uint32_t prebuf;
	int eof;
	int channels;
	int16_t *l;
	switch_size_t llen;
	int16_t *r;
	switch_size_t rlen;
	switch_thread_rwlock_t *rwlock;
};

typedef struct oggshout_context oggshout_context_t;

struct vorbis_codec_priv {
	vorbis_info info;
	vorbis_dsp_state dsp_state;
	ogg_stream_state stream_state;
};

typedef struct vorbis_codec_priv vorbis_codec_priv_t;


static void oggshout_shout_destroy(oggshout_context_t *context)
{
		shout_close(context->shout);
		context->shout = NULL;
}

static void oggshout_vorbis_encoder_destroy(oggshout_context_t *context)
{
	vorbis_codec_priv_t *codec_priv = context->codec_priv;

	if (context->shout) {
		vorbis_block block;
		ogg_packet packet = { 0 };
		ogg_page page = { 0 };

		/* Submit an empty buffer to indicate end of input. */
		vorbis_analysis_wrote(&codec_priv->dsp_state, 0);

		/* Flush remaining buffered audio */
		vorbis_block_init(&codec_priv->dsp_state, &block);

		while (vorbis_analysis_blockout(&codec_priv->dsp_state, &block) == 1) {
			vorbis_analysis(&block, NULL);
			vorbis_bitrate_addblock(&block);

			while (vorbis_bitrate_flushpacket(&codec_priv->dsp_state, &packet) == 1) {
				ogg_stream_packetin(&codec_priv->stream_state, &packet);
				ogg_packet_clear(&packet);
			}
		}

		while (ogg_stream_pageout(&codec_priv->stream_state, &page) > 0) {
			shout_send(context->shout, page.header, page.header_len);
			shout_send(context->shout, page.body, page.body_len);
		}

		oggshout_shout_destroy(context);
	}

	ogg_stream_clear(&codec_priv->stream_state);
	vorbis_dsp_clear(&codec_priv->dsp_state);
	vorbis_info_clear(&codec_priv->info);
	free(codec_priv);

	context->codec_priv = NULL;
}

static void oggshout_opus_encoder_destroy(oggshout_context_t *context)
{
	OpusEncoder *codec_priv = context->codec_priv;

	if (context->shout) {
		/* TODO: Flush remaining buffered audio */

		oggshout_shout_destroy(context);
	}

	opus_encoder_destroy(codec_priv);

	context->codec_priv = NULL;
}

static inline void free_context(oggshout_context_t *context)
{
	if (context) {
		switch_mutex_lock(context->audio_mutex);
		context->err++;
		switch_mutex_unlock(context->audio_mutex);

		if (context->stream_url) {
			int sanity = 0;

			while (context->thread_running) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Waiting for stream to terminate: %s\n", context->stream_url);
				switch_yield(500000);
				if (++sanity > 10) {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Giving up waiting for stream to terminate: %s\n", context->stream_url);
					break;
				}
			}
		}

		switch_thread_rwlock_wrlock(context->rwlock);

		if (context->codec_priv) {
			switch (context->codec) {
				case OGGSHOUT_CODEC_VORBIS:
					oggshout_vorbis_encoder_destroy(context);
					break;
				case OGGSHOUT_CODEC_OPUS:
					oggshout_opus_encoder_destroy(context);
					break;
				default:
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Attempting to destroy unknown encoder %d\n", context->codec);
					break;
			}
		}

		if (context->audio_buffer) {
			switch_buffer_destroy(&context->audio_buffer);
		}

		switch_mutex_destroy(context->audio_mutex);

		switch_thread_rwlock_unlock(context->rwlock);
		switch_thread_rwlock_destroy(context->rwlock);
	}
}

static switch_status_t oggshout_vorbis_encoder_write(oggshout_context_t *context, void *data, size_t len)
{
	vorbis_codec_priv_t *codec_priv = context->codec_priv;
	vorbis_comment vc;
	vorbis_block block;
	float **vorbis_buffers;
	int samples;
	int i = 0;
	int16_t *sample = data;
	int channels = context->channels;
	ogg_packet packet = { 0 };
	ogg_page page = { 0 };
	
	/* Each sample is two bytes, and we can have 1 or 2 channels */
	samples = len / sizeof (int16_t) / channels;

	if (context->err) {
		goto error;
	}

	if (!context->encoder_ready) {
		ogg_packet codec_id = { 0 };
		ogg_packet comment = { 0 };
		ogg_packet code = { 0 };

		vorbis_comment_init(&vc);

		/* Output headers */
		vorbis_analysis_headerout(&codec_priv->dsp_state, &vc, &codec_id, &comment, &code);

		vorbis_comment_clear(&vc);

		ogg_stream_packetin(&codec_priv->stream_state, &codec_id);
		ogg_stream_packetin(&codec_priv->stream_state, &comment);
		ogg_stream_packetin(&codec_priv->stream_state, &code);

		ogg_packet_clear(&code);
		ogg_packet_clear(&comment);
		ogg_packet_clear(&codec_id);

		context->encoder_ready++;

		/* Sending the ogg pages to shout will be handled by a later loop */
	}

	/* Copy the samples into the vorbis buffer, converting to float on the way */
	vorbis_buffers = vorbis_analysis_buffer(&codec_priv->dsp_state, samples);

	if (channels == 1) {
		for (i = 0; i < samples; i++) {
			vorbis_buffers[0][i] = sample[i] / 32768.0f;
		}
	} else if (channels == 2) {
		for (i = 0; i < samples; i++) {
			vorbis_buffers[0][i] = sample[i*2] / 32768.0f;
			vorbis_buffers[1][i] = sample[i*2+1] / 32768.0f;
		}
	}

	vorbis_analysis_wrote(&codec_priv->dsp_state, samples);

	/* Split the buffer into blocks, then analyze/encode the blocks */
	vorbis_block_init(&codec_priv->dsp_state, &block);

	while (vorbis_analysis_blockout(&codec_priv->dsp_state, &block) == 1) {
		vorbis_analysis(&block, NULL);
		vorbis_bitrate_addblock(&block);

		while (vorbis_bitrate_flushpacket(&codec_priv->dsp_state, &packet) == 1) {
			ogg_stream_packetin(&codec_priv->stream_state, &packet);
			ogg_packet_clear(&packet);
		}
	}

	/* Generate the ogg packets, and send them via libshout */
	while (ogg_stream_pageout(&codec_priv->stream_state, &page) > 0) {
		shout_send(context->shout, page.header, page.header_len);
		shout_send(context->shout, page.body, page.body_len);
	}

	return SWITCH_STATUS_SUCCESS;

error:
	return SWITCH_STATUS_GENERR;
}

static switch_status_t oggshout_opus_encoder_write(oggshout_context_t *context, void *data, size_t len)
{
	/* TODO */
	return SWITCH_STATUS_FALSE;
}

#define error_check() if (context->err) goto error;

static void *SWITCH_THREAD_FUNC write_stream_thread(switch_thread_t *thread, void *obj)
{
	oggshout_context_t *context = (oggshout_context_t *) obj;

	switch_thread_rwlock_rdlock(context->rwlock);

	if (context->thread_running) {
		context->thread_running++;
	} else {
		switch_thread_rwlock_unlock(context->rwlock);
		return NULL;
	}

	while (!context->err && context->thread_running) {
		int16_t audio[9600] = { 0 };
		switch_size_t audio_read = 0;
		switch_status_t ret = 0;

		switch_mutex_lock(context->audio_mutex);
		if (context->audio_buffer) {
			audio_read = switch_buffer_read(context->audio_buffer, audio, sizeof(audio));
		} else {
			context->err++;
		}
		switch_mutex_unlock(context->audio_mutex);

		error_check();

		if (!audio_read) {
			audio_read = sizeof(audio);
			memset(audio, 0, sizeof(audio));
		}

		switch (context->codec) {
			case OGGSHOUT_CODEC_VORBIS:
				ret = oggshout_vorbis_encoder_write(context, audio, audio_read);
				break;
			case OGGSHOUT_CODEC_OPUS:
				ret = oggshout_opus_encoder_write(context, audio, audio_read);
				break;
		}

		if (ret != SWITCH_STATUS_SUCCESS) {
			goto error;
		}

		shout_sync(context->shout);
	}

  error:
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Write Thread Done\n");
	switch_thread_rwlock_unlock(context->rwlock);
	context->thread_running = 0;
	return NULL;
}

static switch_status_t launch_write_stream_thread(oggshout_context_t *context)
{
	switch_thread_t *thread;
	switch_threadattr_t *thd_attr = NULL;
	int sanity = 10;

	if (context->err) {
		return SWITCH_STATUS_FALSE;
	}

	context->thread_running = 1;
	switch_threadattr_create(&thd_attr, context->memory_pool);
	switch_threadattr_detach_set(thd_attr, 1);
	switch_threadattr_stacksize_set(thd_attr, SWITCH_THREAD_STACKSIZE);
	switch_thread_create(&thread, thd_attr, write_stream_thread, context, context->memory_pool);

	while (context->thread_running && context->thread_running != 2) {
		switch_yield(100000);
		if (!--sanity)
			return SWITCH_STATUS_GENERR;
	}

	return SWITCH_STATUS_SUCCESS;
}

#define TC_BUFFER_SIZE 1024 * 32

#define CONCAT_LOCATION(_x,_y) _x ":" #_y
#define MAKE_LOCATION(_x,_y) CONCAT_LOCATION(_x,_y)
#define HERE MAKE_LOCATION(__FILE__, __LINE__)

static switch_status_t oggshout_shout_sender_open(oggshout_context_t *context, const char *path)
{
	shout_t *shout = NULL;
	switch_status_t err = SWITCH_STATUS_GENERR;
	char *username, *password, *host, *port, *mount;
	int portno = 0;

	username = switch_core_strdup(context->handle->memory_pool, path);
	if (!(password = strchr(username, ':'))) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to parse password in URL\n");
		goto error;
	}
	*password++ = '\0';
	if (!(host = strchr(password, '@'))) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to parse host in URL\n");
		goto error;
	}
	*host++ = '\0';
	if (!(mount = strchr(host, '/'))) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to parse mount in URL\n");
		goto error;
	}
	*mount++ = '\0';
	if ((port = strchr(host, ':'))) {
		*port++ = '\0';
		if (port) {
			portno = atoi(port);
		}
	}
	if (!portno) {
		portno = 8000;
	}

	shout = shout_new();
	if (!shout) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to allocate shout stream\n");
		err = SWITCH_STATUS_MEMERR;
		goto error;
	}

	if (shout_set_host(shout, host) != SHOUTERR_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to set hostname: %s\n", shout_get_error(context->shout));
		goto error;
	}
	if (shout_set_port(shout, portno) != SHOUTERR_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to set port: %s\n", shout_get_error(context->shout));
		goto error;
	}
	if (shout_set_user(shout, username) != SHOUTERR_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to set username: %s\n", shout_get_error(context->shout));
		goto error;
	}
	if (shout_set_password(shout, password) != SHOUTERR_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to set password: %s\n", shout_get_error(context->shout));
		goto error;
	}
	if (shout_set_protocol(shout, SHOUT_PROTOCOL_HTTP) != SHOUTERR_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to set protocol: %s\n", shout_get_error(context->shout));
		goto error;
	}
	if (shout_set_format(shout, SHOUT_FORMAT_OGG) != SHOUTERR_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to set format: %s\n", shout_get_error(context->shout));
		goto error;
	}
	if (shout_set_mount(shout, mount) != SHOUTERR_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to set mount: %s\n", shout_get_error(context->shout));
		goto error;
	}

	if (shout_open(shout) != SHOUTERR_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to open shoutcast stream: %s\n", shout_get_error(context->shout));
		goto error;
	}

	context->shout = shout;
	return SWITCH_STATUS_SUCCESS;

error:
	if (shout) {
		shout_free(shout);
	}
	context->shout = NULL;

	return err;
}

static switch_status_t oggshout_vorbis_encoder_open(oggshout_context_t *context, const char *path)
{
	int ret;
	switch_status_t err;
	vorbis_codec_priv_t *codec_priv;

	codec_priv = malloc(sizeof (vorbis_codec_priv_t));
	if (!codec_priv) {
		return SWITCH_STATUS_MEMERR;
	}

	context->codec_priv = codec_priv;
	vorbis_info_init(&codec_priv->info);

	switch (globals.vorbis_mode) {
	case OGGSHOUT_MODE_QUALITY:
		ret = vorbis_encode_init_vbr(&codec_priv->info, context->channels, context->samplerate, globals.vorbis_quality);
		break;
	case OGGSHOUT_MODE_VBR:
		ret = ( vorbis_encode_setup_managed(&codec_priv->info, context->channels, context->samplerate, -1, globals.vorbis_bitrate, -1) ||
				vorbis_encode_ctl(&codec_priv->info, OV_ECTL_RATEMANAGE2_SET, NULL) ||
				vorbis_encode_setup_init(&codec_priv->info) );
		break;
	case OGGSHOUT_MODE_MANAGED:
		ret = vorbis_encode_init(&codec_priv->info, context->channels, context->samplerate, globals.vorbis_max_bitrate, globals.vorbis_bitrate, globals.vorbis_min_bitrate);
		break;
	default:
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Vorbis encoding mode not set\n");
		goto error;
	}
	if (ret) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Vorbis encoder initialization failed\n");
		goto error;
	}

	ret = vorbis_analysis_init(&codec_priv->dsp_state, &codec_priv->info);
	if (ret) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Vorbis encoder analysis initialization failed\n");
		goto error;
	}

	err = oggshout_shout_sender_open(context, path);
	if (err != SWITCH_STATUS_SUCCESS) {
		goto error;
	}

	return SWITCH_STATUS_SUCCESS;

error:
	if (codec_priv) {
		vorbis_dsp_clear(&codec_priv->dsp_state);
		vorbis_info_clear(&codec_priv->info);
		free(codec_priv);
		context->codec_priv = NULL;
	}

	return SWITCH_STATUS_GENERR;
}

static switch_status_t opus_error_convert(int error)
{
	switch (error) {
	case OPUS_OK:
		return SWITCH_STATUS_SUCCESS;
	case OPUS_ALLOC_FAIL:
		return SWITCH_STATUS_MEMERR;
	default:
		return SWITCH_STATUS_GENERR;
	}
}

static switch_status_t oggshout_opus_encoder_open(oggshout_context_t *context, const char *path)
{
	int opus_error;
	switch_status_t err;
	OpusEncoder *codec_priv;

	codec_priv = opus_encoder_create(context->samplerate, context->channels, globals.opus_application, &opus_error);
	if (opus_error != OPUS_OK) {
		goto error;
	}

	switch (globals.opus_mode) {
	case OGGSHOUT_MODE_VBR:
		opus_encoder_ctl(codec_priv, OPUS_SET_VBR(1));
		opus_encoder_ctl(codec_priv, OPUS_SET_VBR_CONSTRAINT(0));
		opus_encoder_ctl(codec_priv, OPUS_SET_BITRATE(globals.opus_bitrate));
		break;
	case OGGSHOUT_MODE_MANAGED:
		opus_encoder_ctl(codec_priv, OPUS_SET_VBR(1));
		opus_encoder_ctl(codec_priv, OPUS_SET_VBR_CONSTRAINT(1));
		opus_encoder_ctl(codec_priv, OPUS_SET_BITRATE(globals.opus_bitrate));
		break;
	default:
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Opus encoding mode not set\n");
		goto error;
	}

	context->codec_priv = codec_priv;

	err = oggshout_shout_sender_open(context, path);
	if (err != SWITCH_STATUS_SUCCESS) {
		goto error;
	}

	return SWITCH_STATUS_SUCCESS;

error:
	if (codec_priv) {
		opus_encoder_destroy(codec_priv);
		context->codec_priv = NULL;
	}

	if (opus_error != OPUS_OK) {
		return opus_error_convert(opus_error);
	}

	return SWITCH_STATUS_GENERR;
}

static int pathext(const char *path, const char *ext) {
	int path_len, ext_len;

	path_len = strlen(path);
	ext_len = strlen(ext);

	if (path_len < ext_len) {
		return -1;
	}
	return strcmp(path + path_len - ext_len, ext);
}

#define MY_BUF_LEN 1024*32
#define MY_BLOCK_SIZE MY_BUF_LEN
static switch_status_t oggshout_file_open(switch_file_handle_t *handle, const char *path)
{
	oggshout_context_t *context;
	switch_status_t ret = SWITCH_STATUS_GENERR;

	/* For now, stream reading support is disabled. We only need writing */
	if (switch_test_flag(handle, SWITCH_FILE_FLAG_READ)) {
		return SWITCH_STATUS_FALSE;
	}

	if ((context = switch_core_alloc(handle->memory_pool, sizeof(*context))) == 0) {
		return SWITCH_STATUS_MEMERR;
	}

	if (!handle->samplerate) {
		handle->samplerate = 8000;
	}

	context->memory_pool = handle->memory_pool;
	context->samplerate = handle->samplerate;
	context->handle = handle;

	switch_thread_rwlock_create(&(context->rwlock), context->memory_pool);

	switch_thread_rwlock_rdlock(context->rwlock);

	switch_mutex_init(&context->audio_mutex, SWITCH_MUTEX_NESTED, context->memory_pool);

	context->channels = handle->channels;
	handle->samples = 0;
	handle->format = 0;
	handle->sections = 0;
	handle->speed = 0;
	handle->private_info = context;

	/* Select the codec based off the file extension */
	if (pathext(path, ".ogg") == 0) {
		context->codec = OGGSHOUT_CODEC_VORBIS;
	} else if (pathext(path, ".opus") == 0) {
		context->codec = OGGSHOUT_CODEC_OPUS;
	} else {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Could not determine file format from path\n");
		goto error;
	}

	if (switch_buffer_create_dynamic(&context->audio_buffer, MY_BLOCK_SIZE, MY_BUF_LEN, 0) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Memory Error!\n");
		goto error;
	}

	switch (context->codec) {
		case OGGSHOUT_CODEC_VORBIS:
			ret = oggshout_vorbis_encoder_open(context, path);
			break;
		case OGGSHOUT_CODEC_OPUS:
			ret = oggshout_opus_encoder_open(context, path);
			break;
		default:
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Attempt to initialize unknown encoder %d\n", context->codec);
			break;
	}

	if (ret != SWITCH_STATUS_SUCCESS) {
		goto error;
	}

	switch_thread_rwlock_unlock(context->rwlock);

	return SWITCH_STATUS_SUCCESS;

  error:
	switch_thread_rwlock_unlock(context->rwlock);
	free_context(context);
	return SWITCH_STATUS_GENERR;

}

static switch_status_t shout_file_close(switch_file_handle_t *handle)
{
	oggshout_context_t *context = handle->private_info;

	free_context(context);

	return SWITCH_STATUS_SUCCESS;
}

static switch_status_t shout_file_seek(switch_file_handle_t *handle, unsigned int *cur_sample, int64_t samples, int whence)
{
	return SWITCH_STATUS_FALSE;
}

static switch_status_t shout_file_read(switch_file_handle_t *handle, void *data, size_t *len)
{
	return SWITCH_STATUS_FALSE;
}


static switch_status_t shout_file_write(switch_file_handle_t *handle, void *data, size_t *len)
{
	oggshout_context_t *context;
	size_t nsamples = *len;

	if (!handle) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Error no handle\n");
		return SWITCH_STATUS_FALSE;
	}

	if (!(context = handle->private_info)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Error no context\n");
		return SWITCH_STATUS_FALSE;
	}

	/* If err is set, we are in the process of exiting. Refuse writes. */
	if (context->err) {
		return SWITCH_STATUS_FALSE;
	}

	if (!context->thread_init) {
		switch_status_t ret;
		
		context->thread_init++;

		ret = launch_write_stream_thread(context);
		if (ret != SWITCH_STATUS_SUCCESS) {
			return ret;
		}
	}

	if (context->audio_mutex) {
		switch_mutex_lock(context->audio_mutex);
		if (context->audio_buffer) {
			if (!switch_buffer_write(context->audio_buffer, data, (nsamples * sizeof(int16_t) * handle->channels))) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Buffer error\n");
				context->err++;
			}
		} else {
			context->err++;
		}

		switch_mutex_unlock(context->audio_mutex);
		if (context->err) {
			return SWITCH_STATUS_FALSE;
		}

		handle->sample_count += *len;
		return SWITCH_STATUS_SUCCESS;
	}

	return SWITCH_STATUS_GENERR;
}

static switch_status_t shout_file_set_string(switch_file_handle_t *handle, switch_audio_col_t col, const char *string)
{
	oggshout_context_t *context = handle->private_info;
	switch_status_t status = SWITCH_STATUS_FALSE;

	return SWITCH_STATUS_SUCCESS;

	switch (col) {
	case SWITCH_AUDIO_COL_STR_TITLE:
		if (shout_set_name(context->shout, string) == SHOUTERR_SUCCESS) {
			status = SWITCH_STATUS_SUCCESS;
		} else {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Error setting name: %s\n", shout_get_error(context->shout));
		}
		break;
	case SWITCH_AUDIO_COL_STR_COMMENT:
		if (shout_set_url(context->shout, string) == SHOUTERR_SUCCESS) {
			status = SWITCH_STATUS_SUCCESS;
		} else {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Error setting name: %s\n", shout_get_error(context->shout));
		}
		break;
	case SWITCH_AUDIO_COL_STR_ARTIST:
		if (shout_set_description(context->shout, string) == SHOUTERR_SUCCESS) {
			status = SWITCH_STATUS_SUCCESS;
		} else {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Error setting name: %s\n", shout_get_error(context->shout));
		}
		break;
	default:
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "Value Ignored %d, %s\n", col, string);
		break;
	}

	return status;
}

static switch_status_t shout_file_get_string(switch_file_handle_t *handle, switch_audio_col_t col, const char **string)
{
	return SWITCH_STATUS_FALSE;
}

static switch_status_t load_config(void)
{
	char *cf = "shout.conf";
	switch_xml_t cfg, xml, settings, param;

	memset(&globals, 0, sizeof(globals));
	globals.vorbis_mode = OGGSHOUT_MODE_MANAGED;
	globals.vorbis_bitrate = OGGSHOUT_DEFAULT_BITRATE;
	globals.vorbis_max_bitrate = -1;
	globals.vorbis_min_bitrate = -1;
	globals.opus_mode = OGGSHOUT_MODE_MANAGED;
	globals.opus_application = OPUS_APPLICATION_VOIP;
	globals.opus_bitrate = OGGSHOUT_DEFAULT_BITRATE;

	if (!(xml = switch_xml_open_cfg(cf, &cfg, NULL))) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Open of %s failed\n", cf);
		return SWITCH_STATUS_TERM;
	}

	if ((settings = switch_xml_child(cfg, "settings"))) {
		for (param = switch_xml_child(settings, "param"); param; param = param->next) {
			char *var = (char *) switch_xml_attr_soft(param, "name");
			char *val = (char *) switch_xml_attr_soft(param, "value");

			if (!strcmp(var, "vorbis-mode")) {
				if (!strcmp(val, "quality")) {
					globals.vorbis_mode = OGGSHOUT_MODE_QUALITY;
				} else if (!strcmp(val, "vbr")) {
					globals.vorbis_mode = OGGSHOUT_MODE_VBR;
				} else if (!strcmp(val, "managed")) {
					globals.vorbis_mode = OGGSHOUT_MODE_MANAGED;
				}
			} else if (!strcmp(var, "vorbis-quality")) {
				/* Current acceptable range is -0.1 to 1.0, but this could change... */
				globals.vorbis_quality = atof(val);
			} else if (!strcmp(var, "vorbis-bitrate")) {
				int tmp = atoi(val);
				if (tmp > 0) {
					globals.vorbis_bitrate = tmp;
				}
			} else if (!strcmp(var, "vorbis-max-bitrate")) {
				int tmp = atoi(val);
				if (tmp > 0) {
					globals.vorbis_max_bitrate = tmp;
				}
			} else if (!strcmp(var, "vorbis-min-bitrate")) {
				int tmp = atoi(val);
				if (tmp > 0) {
					globals.vorbis_min_bitrate = tmp;
				}
			} else if (!strcmp(var, "opus-mode")) {
				if (!strcmp(val, "vbr")) {
					globals.opus_mode = OGGSHOUT_MODE_VBR;
				} else if (!strcmp(val, "managed")) {
					globals.opus_mode = OGGSHOUT_MODE_MANAGED;
				}
			} else if (!strcmp(var, "opus-application")) {
				if (!strcmp(val, "voip")) {
					globals.opus_application = OPUS_APPLICATION_VOIP;
				} else if (!strcmp(val, "audio")) {
					globals.opus_application = OPUS_APPLICATION_AUDIO;
				}
			} else if (!strcmp(var, "opus-bitrate")) {
				int tmp = atoi(val);
				if (tmp > 0) {
					globals.opus_bitrate = tmp;
				}
			}
		}
	}


	switch_xml_free(xml);

	return SWITCH_STATUS_SUCCESS;
}

SWITCH_MODULE_LOAD_FUNCTION(mod_oggshout_load)
{
	switch_file_interface_t *file_interface;

	supported_formats[0] = "oggshout";
	supported_formats[1] = "ogg";
	supported_formats[2] = "opus";

	/* connect my internal structure to the blank pointer passed to me */
	*module_interface = switch_loadable_module_create_module_interface(pool, modname);
	file_interface = switch_loadable_module_create_interface(*module_interface, SWITCH_FILE_INTERFACE);
	file_interface->interface_name = modname;
	file_interface->extens = supported_formats;
	file_interface->file_open = oggshout_file_open;
	file_interface->file_close = shout_file_close;
	file_interface->file_read = shout_file_read;
	file_interface->file_write = shout_file_write;
	file_interface->file_seek = shout_file_seek;
	file_interface->file_set_string = shout_file_set_string;
	file_interface->file_get_string = shout_file_get_string;

	shout_init();
	load_config();

	/* indicate that the module should continue to be loaded */
	return SWITCH_STATUS_SUCCESS;
}

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_oggshout_shutdown)
{
	return SWITCH_STATUS_SUCCESS;
}

/* For Emacs:
 * Local Variables:
 * mode:c
 * indent-tabs-mode:t
 * tab-width:4
 * c-basic-offset:4
 * End:
 * For VIM:
 * vim:set softtabstop=4 shiftwidth=4 tabstop=4:
 */
