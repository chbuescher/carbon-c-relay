/*
 * Copyright 2013-2017 Fabian Groffen
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _GNU_SOURCE

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/queue.h>
#include <event.h>

#include "relay.h"
#include "receptor.h"
#include "router.h"
#include "server.h"
#include "collector.h"
#include "dispatcher.h"

enum conntype {
	LISTENER,
	CONNECTION
};

enum listentype {
	PLAN_ACTIVE,
	ACTIVE,
	PLAN_CLOSED,
	CLOSED
};

enum chartype {
	IS_TEXT,
	IS_SEP,
	IS_END,
	IS_OTHER
};

typedef struct _listener {
	int sock;
	char noexpire;
	char isudp;
	enum listentype state;
	struct event ev_read;
	dispatcher *self;
	TAILQ_ENTRY(_listener) entries; /* pointers to the next and previous entries in the tail queue */
} listener;

typedef struct _connection {
	int sock;
	char srcaddr[24];  /* string representation of source address */
	char buf[METRIC_BUFSIZ];
	int buflen;
	dispatcher *self;
	listener *list;
	struct event ev_read;
	int metric_sent;
} connection;

typedef struct _metric_block {
	char srcaddr[24];  /* string representation of source address */
	char metric[METRIC_MAXLEN];
	char *buffer;
	size_t buf_len; 
	destination dests[CONN_DESTS_SIZE];
	size_t destlen;
	TAILQ_ENTRY(_metric_block) entries; /* pointers to the next and previous entries in the tail queue */
	char _buf;
} metric_block;

struct _dispatcher {
	pthread_t tid;
	enum conntype type;
	char id;
	size_t queuesize;
	size_t metrics;
	size_t blackholes;
	size_t ticks;
	size_t sleeps;
	size_t prevmetrics;
	size_t prevblackholes;
	size_t prevticks;
	size_t prevsleeps;
	char keep_running;  /* full byte for atomic access */
	router *rtr;
	router *pending_rtr;
	char route_refresh_pending;  /* full byte for atomic access */
	char hold:1;
	char *allowed_chars;
	pthread_mutex_t conn_queue_lock;
	pthread_cond_t conn_queue_cond;
	struct event timer_ev;
	TAILQ_HEAD(, _metric_block) metric_block_head;
};

static size_t acceptedconnections = 0;
static size_t closedconnections = 0;
static unsigned int sockbufsize = 0;
static unsigned int idx = 0;

static TAILQ_HEAD(, _listener) register_listener_head;
static pthread_mutex_t register_listener_lock;
static struct event_base *ev_base;

static char ctype_isinit = 0;
static enum chartype ctype[256];

extern dispatcher **workers;
extern char workercnt;


/**
 * Helper function to try and be helpful to the user.  If errno
 * indicates no new fds could be made, checks what the current max open
 * files limit is, and if it's close to what we have in use now, write
 * an informative message to stderr.
 */
void
dispatch_check_rlimit_and_warn(void)
{
	if (errno == EISCONN || errno == EMFILE) {
		struct rlimit ofiles;
		/* rlimit can be changed for the running process (at least on
		 * Linux 2.6+) so refetch this value every time, should only
		 * occur on errors anyway */
		if (getrlimit(RLIMIT_NOFILE, &ofiles) < 0)
			ofiles.rlim_max = 0;
		if (ofiles.rlim_max != RLIM_INFINITY && ofiles.rlim_max > 0)
			logerr("process configured maximum connections = %d, "
					"consider raising max open files/max descriptor limit\n",
					(int)ofiles.rlim_max);
	}
}

void dispatch_initlisteners(void) {
		pthread_mutex_init(&register_listener_lock, NULL);

		pthread_mutex_lock(&register_listener_lock);
		TAILQ_INIT(&register_listener_head);
		pthread_mutex_unlock(&register_listener_lock);
}

void dispatch_destroylisteners(void) {
		pthread_mutex_destroy(&register_listener_lock);
}

/**
 * Adds an (initial) listener socket to the chain of connections.
 * Listener sockets are those which need to be accept()-ed on.
 */
int
dispatch_addlistener(int sock, char noexpire, char isudp)
{
	listener *list;

	(void) fcntl(sock, F_SETFL, O_NONBLOCK);

	pthread_mutex_lock(&register_listener_lock);

	/* insert new entry in queue */
	list = malloc(sizeof(listener));
	if (list == NULL)
		return -1;
	list->sock = sock;
	list->noexpire = noexpire;
	list->isudp = isudp;
	list->state = PLAN_ACTIVE;
	list->self = NULL;

	TAILQ_INSERT_TAIL(&register_listener_head, list, entries);
	pthread_mutex_unlock(&register_listener_lock);

	return 0;
}

/**
 * Remove listener from the listeners list.  Each removal will incur a
 * global lock.  Frequent usage of this function is not anticipated.
 */
void
dispatch_removelistener(int sock)
{
	listener *list;

	close(sock);
	pthread_mutex_lock(&register_listener_lock);
	TAILQ_FOREACH(list, &register_listener_head, entries) {
		if (list->sock == sock) {
			list->state = PLAN_CLOSED;
		}
	}
	pthread_mutex_unlock(&register_listener_lock);
}


/**
 * Adds a pseudo-listener for datagram (UDP) sockets, which is pseudo,
 * for in fact it adds a new connection, but makes sure that connection
 * won't be closed after being idle, and won't count that connection as
 * an incoming connection either.
 */
int
dispatch_addlistener_udp(int sock)
{
	dispatch_addlistener(sock, 1, 1);

	return 0;
}

int
dispatch_addlistener_tcp(int sock)
{
	return dispatch_addlistener(sock, 0, 0);
}

int
dispatch_addlistener_aggr(int sock)
{
	return dispatch_addlistener(sock, 1, 0);
}


inline static char
dispatch_process_dests(metric_block *metric, dispatcher *self, char *firstspace)
{
	int i;
	char force;
	struct timeval now;

	gettimeofday(&now, NULL);

	/* perform routing of this metric */
	tracef("dispatcher %d, metric %s",
			self->id, metric->metric);
	__sync_add_and_fetch(&(self->blackholes),
			router_route(self->rtr,
			metric->dests, &metric->destlen, CONN_DESTS_SIZE,
			metric->srcaddr,
			metric->metric, firstspace));
	tracef("dispatcher %d, destinations %zd\n",
			self->id, metric->destlen);

	if (metric->destlen > 0) {
		force = 1;
		for (i = 0; i < metric->destlen; i++) {
			tracef("dispatcher %d, metric %s, queueing to %s:%d\n",
					self->id, metric->dests[i].metric,
					server_ip(metric->dests[i].dest),
					server_port(metric->dests[i].dest));
			if (server_send(metric->dests[i].dest, metric->dests[i].metric, force) == 0)
				break;
		}
		if (i != metric->destlen) {
			metric->destlen -= i;
			memmove(&metric->dests[0], &metric->dests[i],
					(sizeof(destination) * metric->destlen));
			return 0;
		} else {
			/* finally "complete" this metric */
			metric->destlen = 0;
		}
	}

	return 1;
}

void
dispatch_initctype(char *allowed_chars) {
	unsigned short int i;
	
	for (i = 0; i < 256; i++) {
		if (i == '\n' || i == '\r' || i == 0) {
			ctype[i] = IS_END;
		} else if (i == ' ' || i == '\t' || i == '.') {
			ctype[i] = IS_SEP;
		} else if ((i >= 'a' && i <= 'z') ||
				(i >= 'A' && i <= 'Z') ||
				(i >= '0' && i <= '9') ||
				strchr(allowed_chars, i))
		{
			ctype[i] = IS_TEXT;
		}
		else {
			ctype[i] = IS_OTHER;
		}
	}

	ctype_isinit = 1;
}

int
dispatch_parsebuf(dispatcher *self, metric_block *mblock, struct timeval start) {
	char *p, *q, *firstspace, res;
	int metric_sent = 0;
	enum chartype ct;

	/* metrics look like this: metric_path value timestamp\n
	 * due to various messups we need to sanitise the
	 * metrics_path here, to ensure we can calculate the metric
	 * name off the filesystem path (and actually retrieve it in
	 * the web interface). */
	q = mblock->metric;
	firstspace = NULL;

	for (p = mblock->buffer; *p; p++) {
		ct = ctype[(unsigned char) *p];
		if (ct == IS_TEXT) {
			/* copy char */
			*q++ = *p;
		} else if (ct == IS_SEP) {
			/* separator */
			if (q == mblock->metric) {
				/* make sure we skip this on next iteration to
				 * avoid an infinite loop, issues #8 and #51 */
				continue;
			}
			if (*p == '\t')
				*p = ' ';
			if (*p == ' ' && firstspace == NULL) {
				if (*(q - 1) == '.')
					q--;  /* strip trailing separator */
				firstspace = q;
				*q++ = ' ';
			} else {
				/* metric_path separator or space,
				 * - duplicate elimination
				 * - don't start with separator/space */
				if (*(q - 1) != *p && (q - 1) != firstspace)
					*q++ = *p;
			}
		} else if (ct == IS_END) {
			/* end of metric */

			/* just a newline on it's own? some random garbage? skip */
			if (q == mblock->metric || firstspace == NULL) {
				q = mblock->metric;
				firstspace = NULL;
				continue;
			}

			__sync_add_and_fetch(&(self->metrics), 1);
			*q++ = '\n';
			*q = '\0';  /* can do this because we substract one from buf */

			/* send the metric to where it is supposed to go */
			metric_sent++;
			res = dispatch_process_dests(mblock, self, firstspace);

			/* restart building new one from the start */
			q = mblock->metric;
			firstspace = NULL;

			if (res == 0)
				break;
		} else if (firstspace != NULL)
		{
			/* copy char */
			*q++ = *p;
		} else {
			/* something barf, replace by underscore */
			*q++ = '_';
		}
	}
	
	return metric_sent;
}

/**
 * This function will be called by libevent when the client socket is
 * ready for reading.
 */
void
dispatch_connread_cb(int fd, short ev, void *arg)
{
	connection *conn = (connection *)arg;
	dispatcher *self = conn->self;
	char *lastnl;
	int len, buf_len;
	metric_block *mblock;
	dispatcher *disp;
	struct timeval start, stop;

	gettimeofday(&start, NULL);

	if (__sync_bool_compare_and_swap(&(self->keep_running), 1, 1)) {
		len = read(fd,
					conn->buf + conn->buflen,
					(sizeof(conn->buf) - 1) - conn->buflen);

		if (len > 0) {
			/* try to read more data, if that succeeds, or we still have data
			 * left in the buffer, try to process the buffer */
			conn->buflen += len;
			tracef("dispatcher 0, connfd %d, read %d bytes from socket\n",
					conn->sock, len);

			// search last newline
			lastnl = (char *) memrchr(conn->buf, '\n', conn->buflen);

			if (lastnl != NULL) {
				/* copy the buffer to new metric block
				 * alloc struct + buffer */
				buf_len = lastnl - conn->buf + 1;
				if (buf_len > 1) {
					mblock = malloc(sizeof(metric_block) + buf_len);
					if (mblock) {
						mblock->buf_len = buf_len;
						mblock->buffer = &(mblock->_buf);
						memcpy(mblock->buffer, conn->buf, mblock->buf_len);
						mblock->buffer[mblock->buf_len] = 0;
						strcpy(mblock->srcaddr, conn->srcaddr);

						disp = workers[++idx % workercnt + 1];
						pthread_mutex_lock(&disp->conn_queue_lock);
						/* check if metric block queue in selected worker isn't full */
						if (disp->queuesize < self->queuesize) {
							TAILQ_INSERT_TAIL(&disp->metric_block_head, mblock, entries);
							disp->queuesize++;
							pthread_cond_signal(&disp->conn_queue_cond);
						}
						else {
							/* free metric block when queue is full */
							free(mblock);
						}
						pthread_mutex_unlock(&disp->conn_queue_lock);
					}
				}

				/* move remaining stuff to the front */
				conn->buflen -= buf_len;
				memmove(conn->buf, lastnl + 1, conn->buflen);
			}
			/* prevent overflow of buffer with junk */
			else if (conn->buflen > METRIC_MAXLEN) {
				conn->buflen -= METRIC_MAXLEN;
				memmove(conn->buf, conn->buf + METRIC_MAXLEN + 1, conn->buflen);
			}
		}

		gettimeofday(&stop, NULL);
		__sync_add_and_fetch(&(self->ticks), timediff(start, stop));

		if (len == -1 && (errno == EINTR ||
					errno == EAGAIN ||
					errno == EWOULDBLOCK))
		{
			/* nothing available/no work done */
			if (!conn->list->noexpire)
			{
				/* force close connection below */
				len = 0;
			} else {
				return;
			}
		}

		if (len == -1 || len == 0 || conn->list->isudp) {  /* error + EOF */
			/* we also disconnect the client in this case if our reading
			 * buffer is full, but we still need more (read returns 0 if the
			 * size argument is 0) -> this is good, because we can't do much
			 * with such client */

			if (conn->list->noexpire) {
				/* reset buffer only (UDP) and move on */
				conn->buflen = 0;
			}
			else {
				/* close the socket, remove
				 * the event and free the client structure. */
				close(conn->sock);
				__sync_add_and_fetch(&closedconnections, 1);
				event_del(&conn->ev_read);
				free(conn);
			}
		}
	}
}

/**
 * This function will be called by libevent when there is a connection
 * ready to be accepted.
 */
void
dispatch_accept_cb(int fd, short ev, void *arg)
{
	listener *list = (listener *)arg;
	dispatcher *self = list->self;

	int client_fd;
	struct sockaddr_in6 client_addr;
	socklen_t client_len = sizeof(client_addr);
	connection *client;
	struct timeval start, stop;

	gettimeofday(&start, NULL);
	if (list->noexpire) {
		client_fd = fd;
	}
	else {
		/* Accept the new connection. */
		client_fd = accept(fd, (struct sockaddr *)&client_addr, &client_len);
		if (client_fd == -1) {
			logerr("accept failed");
			gettimeofday(&stop, NULL);
			__sync_add_and_fetch(&(self->ticks), timediff(start, stop));
			return;
		}

		/* Set the client socket to non-blocking mode. */
		(void) fcntl(client_fd, F_SETFL, O_NONBLOCK);

		if (sockbufsize > 0) {
			if (setsockopt(client_fd, SOL_SOCKET, SO_RCVBUF,
					&sockbufsize, sizeof(sockbufsize)) != 0)
				;
		}
	}

	__sync_add_and_fetch(&acceptedconnections, 1);

	/* We've accepted a new client, allocate a client object to
	 * maintain the state of this client. */
	// start work
	
	client = calloc(1, sizeof(connection));
	if (client == NULL)
		logerr("malloc failed");

	client->sock = client_fd;
	client->buflen = 0;
	client->list = list;
	client->self = self;

	/* figure out who's calling */
	if (getpeername(client_fd, (struct sockaddr *)&client_addr, &client_len) == 0) {
		snprintf(client->srcaddr, sizeof(client->srcaddr),
				"(unknown)");
		switch (client_addr.sin6_family) {
			case PF_INET:
				inet_ntop(client_addr.sin6_family,
						&((struct sockaddr_in *)&client_addr)->sin_addr,
						client->srcaddr, sizeof(client->srcaddr));
				break;
			case PF_INET6:
				inet_ntop(client_addr.sin6_family, &client_addr.sin6_addr,
						client->srcaddr, sizeof(client->srcaddr));
				break;
		}
	}
	else {
		snprintf(client->srcaddr, sizeof(client->srcaddr),
				"(internal)");
	}

	/* Setup the read event, libevent will call dispatch_connread_cb() whenever
	 * the clients socket becomes read ready.  We also make the
	 * read event persistent so we don't have to re-add after each
	 * read. */
	event_set(&client->ev_read, client_fd, EV_READ|EV_PERSIST, dispatch_connread_cb, 
	    client);

	/* Setting up the event does not activate, add the event so it
	 * becomes active. */
	event_add(&client->ev_read, NULL);

	gettimeofday(&stop, NULL);
	__sync_add_and_fetch(&(self->ticks), timediff(start, stop));
}


static void dispatch_timer_cb (int fd, short flags, void *arg) {
	dispatcher *self = (dispatcher *)arg;
	listener *list;

	/* check if we have to leave event loop */
	if (__sync_bool_compare_and_swap(&(self->keep_running), 1, 1)) {
		struct timeval tv, start, stop;
		gettimeofday(&start, NULL);

		/* register/deregister listeners in libevent
		 * in same thread because of threading issues in libevent 1.x
		 */
		pthread_mutex_lock(&register_listener_lock);
		TAILQ_FOREACH(list, &register_listener_head, entries) {
			if (PLAN_CLOSED == list->state) {
				event_del(&(list->ev_read));
				close(list->sock);

				TAILQ_REMOVE(&register_listener_head, list, entries);
				free(list);
				break;
			}
			else if (PLAN_ACTIVE == list->state) {
				list->self = self;
				event_set(&(list->ev_read), list->sock, EV_READ|EV_PERSIST, dispatch_accept_cb, list);
				event_add(&(list->ev_read), NULL);
				list->state = ACTIVE;
			}
		}
		pthread_mutex_unlock(&register_listener_lock);

		/* and reinsert timer event */
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		evtimer_add(&self->timer_ev, &tv);

		gettimeofday(&stop, NULL);
		__sync_add_and_fetch(&(self->ticks), timediff(start, stop));
	}
	else {
		/* shutdown event loop
		 * cleanup listener queue */
		pthread_mutex_lock(&register_listener_lock);
		while ((list = TAILQ_FIRST(&register_listener_head))) {
			if (PLAN_ACTIVE != list->state) {
				event_del(&(list->ev_read));
				if (ACTIVE == list->state)
					close(list->sock);
			}

			TAILQ_REMOVE(&register_listener_head, list, entries);
			free(list);
		}
		pthread_mutex_unlock(&register_listener_lock);

		event_base_loopexit(ev_base, NULL);
	}
}

static void *
dispatch_runner(void *arg)
{
	dispatcher *self = (dispatcher *)arg;

	self->metrics = 0;
	self->blackholes = 0;
	self->ticks = 0;
	self->sleeps = 0;
	self->prevmetrics = 0;
	self->prevblackholes = 0;
	self->prevticks = 0;
	self->prevsleeps = 0;

	pthread_mutex_init(&self->conn_queue_lock, NULL);
	pthread_cond_init(&self->conn_queue_cond, NULL);

	if (self->type == LISTENER) {
		struct timeval tv;

		/* Initialize libevent. */
		ev_base = event_init();

		/* set up timer. */
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		evtimer_set(&self->timer_ev, dispatch_timer_cb, self);
		evtimer_add(&self->timer_ev, &tv);

		/* Start the libevent event loop. */
		event_base_dispatch(ev_base);

		event_base_free(ev_base);

	} else if (self->type == CONNECTION) {
		struct timeval start, stop;
		metric_block *mblock;

		TAILQ_INIT(&self->metric_block_head);
		self->queuesize = 0;
		
		while (__sync_bool_compare_and_swap(&(self->keep_running), 1, 1)) {
			if (__sync_bool_compare_and_swap(&(self->route_refresh_pending), 1, 1)) {
				self->rtr = self->pending_rtr;
				self->pending_rtr = NULL;
				__sync_bool_compare_and_swap(&(self->route_refresh_pending), 1, 0);
				self->hold = 0;
			}

			pthread_mutex_lock(&self->conn_queue_lock);
			gettimeofday(&start, NULL);
			if (!(mblock = TAILQ_FIRST(&self->metric_block_head))) {
				/* nothing to do, wait */
				pthread_cond_wait(&self->conn_queue_cond, &self->conn_queue_lock);
				pthread_mutex_unlock(&self->conn_queue_lock);
				gettimeofday(&stop, NULL);
				__sync_add_and_fetch(&(self->sleeps), timediff(start, stop));
			}
			else {
				/* got data */
				TAILQ_REMOVE(&self->metric_block_head, mblock, entries);
				self->queuesize--;
				pthread_mutex_unlock(&self->conn_queue_lock);
				dispatch_parsebuf(self, mblock, start);
				free(mblock);
				gettimeofday(&stop, NULL);
				__sync_add_and_fetch(&(self->ticks), timediff(start, stop));
			}
		}

	} else {
		logerr("huh? unknown self type!\n");
	}

	return NULL;
}

/**
 * Starts a new dispatcher for the given type and with the given id.
 * Returns its handle.
 */
static dispatcher *
dispatch_new(char id, enum conntype type, router *r, char *allowed_chars, size_t queuesize)
{
	dispatcher *ret = malloc(sizeof(dispatcher));

	if (ret == NULL)
		return NULL;

	ret->id = id;
	ret->type = type;
	ret->keep_running = 1;
	ret->rtr = r;
	ret->route_refresh_pending = 0;
	ret->hold = 0;
	ret->allowed_chars = allowed_chars;
	ret->queuesize = queuesize;

	ret->metrics = 0;
	ret->blackholes = 0;
	ret->ticks = 0;
	ret->sleeps = 0;
	ret->prevmetrics = 0;
	ret->prevblackholes = 0;
	ret->prevticks = 0;
	ret->prevsleeps = 0;

	if (pthread_create(&ret->tid, NULL, dispatch_runner, ret) != 0) {
		free(ret);
		return NULL;
	}

	return ret;
}

static char globalid = 0;

/**
 * Starts a new dispatcher specialised in handling incoming connections
 * (and putting them on the queue for handling the connections).
 */
dispatcher *
dispatch_new_listener(unsigned int nsockbufsize, size_t queuesize)
{
	char id = globalid++;
	sockbufsize = nsockbufsize;
	return dispatch_new(id, LISTENER, NULL, NULL, queuesize);
}

/**
 * Starts a new dispatcher specialised in handling incoming data on
 * existing connections.
 */
dispatcher *
dispatch_new_connection(router *r, char *allowed_chars)
{
	char id = globalid++;
	if (! ctype_isinit)
		dispatch_initctype(allowed_chars);
	return dispatch_new(id, CONNECTION, r, allowed_chars, 0);
}

/**
 * Signals this dispatcher to stop whatever it's doing.
 */
void
dispatch_stop(dispatcher *d)
{
	__sync_bool_compare_and_swap(&(d->keep_running), 1, 0);
}

/**
 * Shuts down dispatcher d.  Returns when the dispatcher has terminated.
 */
void
dispatch_shutdown(dispatcher *d)
{
	dispatch_stop(d);
	pthread_mutex_lock(&d->conn_queue_lock);
	pthread_cond_signal(&d->conn_queue_cond);
	pthread_mutex_unlock(&d->conn_queue_lock);
	pthread_join(d->tid, NULL);
}

/**
 * Free up resources taken by dispatcher d.  The caller should make sure
 * the dispatcher has been shut down at this point.
 */
void
dispatch_free(dispatcher *d)
{
	pthread_cond_destroy(&d->conn_queue_cond);
	pthread_mutex_destroy(&d->conn_queue_lock);
	free(d);
}

/**
 * Requests this dispatcher to stop processing connections.  As soon as
 * schedulereload finishes reloading the routes, this dispatcher will
 * un-hold and continue processing connections.
 * Returns when the dispatcher is no longer doing work.
 */

inline void
dispatch_hold(dispatcher *d)
{
	d->hold = 1;
}

/**
 * Schedules routes r to be put in place for the current routes.  The
 * replacement is performed at the next cycle of the dispatcher.
 */
inline void
dispatch_schedulereload(dispatcher *d, router *r)
{
	d->pending_rtr = r;
	__sync_bool_compare_and_swap(&(d->route_refresh_pending), 0, 1);
}

/**
 * Returns true if the routes scheduled to be reloaded by a call to
 * dispatch_schedulereload() have been activated.
 */
inline char
dispatch_reloadcomplete(dispatcher *d)
{
	return __sync_bool_compare_and_swap(&(d->route_refresh_pending), 0, 0);
}

/**
 * Returns the wall-clock time in milliseconds consumed by this dispatcher.
 */
inline size_t
dispatch_get_ticks(dispatcher *self)
{
	return __sync_add_and_fetch(&(self->ticks), 0);
}

/**
 * Returns the wall-clock time consumed since last call to this
 * function.
 */
inline size_t
dispatch_get_ticks_sub(dispatcher *self)
{
	size_t d = dispatch_get_ticks(self) - self->prevticks;
	self->prevticks += d;
	return d;
}

/**
 * Returns the wall-clock time in milliseconds consumed while sleeping
 * by this dispatcher.
 */
inline size_t
dispatch_get_sleeps(dispatcher *self)
{
	return __sync_add_and_fetch(&(self->sleeps), 0);
}

/**
 * Returns the wall-clock time consumed while sleeping since last call
 * to this function.
 */
inline size_t
dispatch_get_sleeps_sub(dispatcher *self)
{
	size_t d = dispatch_get_sleeps(self) - self->prevsleeps;
	self->prevsleeps += d;
	return d;
}

/**
 * Returns the number of metrics dispatched since start.
 */
inline size_t
dispatch_get_metrics(dispatcher *self)
{
	return __sync_add_and_fetch(&(self->metrics), 0);
}

/**
 * Returns the number of metrics dispatched since last call to this
 * function.
 */
inline size_t
dispatch_get_metrics_sub(dispatcher *self)
{
	size_t d = dispatch_get_metrics(self) - self->prevmetrics;
	self->prevmetrics += d;
	return d;
}

/**
 * Returns the number of metrics that were explicitly or implicitly
 * blackholed since start.
 */
inline size_t
dispatch_get_blackholes(dispatcher *self)
{
	return __sync_add_and_fetch(&(self->blackholes), 0);
}

/**
 * Returns the number of metrics that were blackholed since last call to
 * this function.
 */
inline size_t
dispatch_get_blackholes_sub(dispatcher *self)
{
	size_t d = dispatch_get_blackholes(self) - self->prevblackholes;
	self->prevblackholes += d;
	return d;
}

/**
 * Returns the length of the metric queue.
 */
inline size_t
dispatch_get_queuelen(dispatcher *self)
{
	return __sync_add_and_fetch(&(self->queuesize), 0);
}

/**
 * Returns the number of accepted connections thusfar.
 */
inline size_t
dispatch_get_accepted_connections(void)
{
	return __sync_add_and_fetch(&(acceptedconnections), 0);
}

/**
 * Returns the number of closed connections thusfar.
 */
inline size_t
dispatch_get_closed_connections(void)
{
	return __sync_add_and_fetch(&(closedconnections), 0);
}
