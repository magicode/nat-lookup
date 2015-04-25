
#include <node.h>
#include <v8.h>

#include <node_buffer.h>
#include <node_object_wrap.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <math.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
//#include <netinet/ipl.h>
//#include <netinet/ip_compat.h>
//#include <netinet/ip_fil.h>
//#include <netinet/ip_nat.h>
//#include <ip_nat.h>
#include <string.h>
#include <fcntl.h>
#include <linux/netfilter_ipv4.h>
#include <errno.h>

using namespace node;
using namespace v8;






struct Baton {
	Persistent<Function> callback;
	struct sockaddr_in lookup;
	int fd;
	bool success;
	int errnum;
	int64_t idDebug;
};


int64_t now(void) {

    struct timespec tms;

    /* The C11 way */
    /* if (! timespec_get(&tms, TIME_UTC)) { */

    /* POSIX.1-2008 way */
    if (clock_gettime(CLOCK_REALTIME,&tms)) {
        return -1;
    }
    /* seconds, multiplied with 1 million */
    int64_t micros = tms.tv_sec * 1000000;
    /* Add full microseconds */
    micros += tms.tv_nsec/1000;
    /* round up if necessary */
    if (tms.tv_nsec % 1000 >= 500) {
        ++micros;
    }
    return micros;
}


static void NatLookupWork(uv_work_t* req) {

	Baton* baton = static_cast<Baton*>(req->data);

	socklen_t len = sizeof(struct sockaddr_in);
	printf("nlp-%ld-4-%d-%ld\n" , baton->idDebug , baton->fd , now());
	memset(&baton->lookup, 0, sizeof(baton->lookup));

	if (getsockopt( baton->fd, IPPROTO_IP, SO_ORIGINAL_DST, &baton->lookup, &len ) != 0){
		baton->success = false;
		baton->errnum = errno;
	} else {
		baton->success = true;
	}
	printf("nlp-%ld-5-%d-%ld\n" , baton->idDebug , baton->fd , now() );
}

static void NatLookupAfter(uv_work_t* req) {

	Baton* baton = static_cast<Baton*>(req->data);
	printf("nlp-%ld-6-%d-%ld\n" , baton->idDebug , baton->fd  , now());
	if (baton->success) {

		const unsigned argc = 3;
		Handle<Value> argv[argc] = {
			Local<Value>::New(Null()),
			Local<Value>::New(String::New(inet_ntoa(baton->lookup.sin_addr))),
			Local<Value>::New(Integer::New(ntohs(baton->lookup.sin_port))),
		};

		TryCatch try_catch;
		baton->callback->Call(Context::GetCurrent()->Global(), argc, argv);
		if (try_catch.HasCaught())
			FatalException(try_catch);

	} else {
		Handle<Value> err ;

		if(baton->errnum != 0)
			err = Exception::Error(String::New(strerror(baton->errnum)));
		else
			err = Exception::Error(String::New("error"));

		const unsigned argc = 1;
		Handle<Value> argv[argc] = {err};

		TryCatch try_catch;
		baton->callback->Call(Context::GetCurrent()->Global(), argc, argv);
		if (try_catch.HasCaught())
			FatalException(try_catch);
	}


	printf("nlp-%ld-7-%d-%ld\n" , baton->idDebug , baton->fd , now());
	baton->callback.Dispose();
	delete baton;
	delete req;

	printf("nlp-%ld-8-%d-%ld\n" , baton->idDebug , baton->fd , now());
}



static Handle<Value> natLookup(const Arguments& args) {
	HandleScope scope;

	if (args.Length() < 2) {
		return ThrowException(
				Exception::TypeError(String::New("Expecting 2 arguments")));
	}

	if (!args[1]->IsFunction()) {
		return ThrowException(
				Exception::TypeError(
						String::New(
								"2 argument must be a callback function")));
	}


	uv_work_t *req  = new uv_work_t;
	Baton* baton = new Baton;
	req->data = baton;
	baton->callback = Persistent < Function > ::New(Local<Function>::Cast(args[1]));
	baton->success = false;
	baton->errnum = 0;

	baton->fd = args[0]->Int32Value();
	baton->idDebug = args[2]->IntegerValue();

	printf("nlp-%ld-2-%d-%ld\n" , baton->idDebug , baton->fd , now());

	uv_queue_work(uv_default_loop(), req, NatLookupWork, (uv_after_work_cb)NatLookupAfter );

	printf("nlp-%ld-3-%d-%ld\n" , baton->idDebug , baton->fd , now());

	return scope.Close(v8::Undefined());

}


static Handle<Value> natLookupSync(const Arguments& args) {
	HandleScope scope;

	if (args.Length() < 1) {
		return ThrowException(
				Exception::TypeError(String::New("Expecting 2 arguments")));
	}

	int fd = args[0]->Int32Value();

	struct sockaddr_in lookup;

	socklen_t len = sizeof(struct sockaddr_in);

	memset(&lookup, 0, len );


	Local<Object> obj = Object::New();

	if (getsockopt( fd , IPPROTO_IP, SO_ORIGINAL_DST, &lookup, &len ) != 0){
		obj->Set(String::New("error"), String::New( strerror( errno ) ) );

	} else {
		obj->Set(String::New("ip"), Local<Value>::New(String::New(inet_ntoa(lookup.sin_addr))) );
		obj->Set(String::New("port"), Local<Value>::New(Integer::New(ntohs(lookup.sin_port))) );
	}

	return scope.Close(obj);
}


//extern "C" {
	void init(Handle<Object> target) {
		target->Set(String::NewSymbol("natLookup"), FunctionTemplate::New(natLookup)->GetFunction());
		target->Set(String::NewSymbol("natLookupSync"), FunctionTemplate::New(natLookupSync)->GetFunction());
	}

	NODE_MODULE(natlookup, init);
//}
