
#include <nan.h>
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
#include <time.h>

using namespace node;
using namespace v8;






struct Baton {
	Nan::Callback *callback;
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
	//printf("nlp-%ld-4-%d-%ld\n" , baton->idDebug , baton->fd , now());
	memset(&baton->lookup, 0, sizeof(baton->lookup));

	if (getsockopt( baton->fd, IPPROTO_IP, SO_ORIGINAL_DST, &baton->lookup, &len ) != 0){
		baton->success = false;
		baton->errnum = errno;
	} else {
		baton->success = true;
	}
	//printf("nlp-%ld-5-%d-%ld\n" , baton->idDebug , baton->fd , now() );
}

static void NatLookupAfter(uv_work_t* req) {
	Nan::HandleScope scope;
	
	Baton* baton = static_cast<Baton*>(req->data);
	//printf("nlp-%ld-6-%d-%ld\n" , baton->idDebug , baton->fd  , now());
	if (baton->success) {

		const unsigned argc = 3;
		Local<Value> argv[argc] = {
			Nan::Null(),
			Nan::New(inet_ntoa(baton->lookup.sin_addr)).ToLocalChecked(),
			Nan::New(ntohs(baton->lookup.sin_port)),
		};

		Nan::TryCatch try_catch;
		baton->callback->Call(Nan::GetCurrentContext()->Global(), argc, argv);
		if (try_catch.HasCaught())
			Nan::FatalException(try_catch);

	} else {
		Local<Value> err ;

		if(baton->errnum != 0)
			err = Exception::Error(Nan::New(strerror(baton->errnum)).ToLocalChecked());
		else
			err = Exception::Error(Nan::New("error").ToLocalChecked());

		const unsigned argc = 1;
		Local<Value> argv[argc] = {err};

		Nan::TryCatch try_catch;
		baton->callback->Call(Nan::GetCurrentContext()->Global(), argc, argv);
		if (try_catch.HasCaught())
			Nan::FatalException(try_catch);
	}


	//printf("nlp-%ld-7-%d-%ld\n" , baton->idDebug , baton->fd , now());
	//baton->callback->Dispose();
	delete baton->callback;
	delete baton;
	delete req;

	//printf("nlp-%ld-8-%d-%ld\n" , baton->idDebug , baton->fd , now());
}



NAN_METHOD(natLookup) {
	Nan::HandleScope scope;

	if (info.Length() < 2) {
		return Nan::ThrowError("Expecting 2 arguments");
	}

	if (!info[1]->IsFunction()) {
		return Nan::ThrowError("2 argument must be a callback function");
	}


	uv_work_t *req  = new uv_work_t;
	Baton* baton = new Baton;
	req->data = baton;
	baton->callback = new Nan::Callback(info[1].As<v8::Function>());
	baton->success = false;
	baton->errnum = 0;

	baton->fd = info[0]->Int32Value();
	baton->idDebug = info[2]->IntegerValue();

	//printf("nlp-%ld-2-%d-%ld\n" , baton->idDebug , baton->fd , now());

	uv_queue_work(uv_default_loop(), req, NatLookupWork, (uv_after_work_cb)NatLookupAfter );

	//printf("nlp-%ld-3-%d-%ld\n" , baton->idDebug , baton->fd , now());

	info.GetReturnValue().SetUndefined();
}


NAN_METHOD(natLookupSync) {
	Nan::HandleScope scope;

	if (info.Length() < 1) {
		return  Nan::ThrowError("Expecting 2 arguments");
	}

	int fd = info[0]->Int32Value();

	struct sockaddr_in lookup;

	socklen_t len = sizeof(struct sockaddr_in);

	memset(&lookup, 0, len );


	Local<Object> obj = Nan::New<v8::Object>();

	if (getsockopt( fd , IPPROTO_IP, SO_ORIGINAL_DST, &lookup, &len ) != 0){
		obj->Set(Nan::New("error").ToLocalChecked(), Nan::New( strerror( errno ) ).ToLocalChecked() );

	} else {
		obj->Set(Nan::New("ip").ToLocalChecked() , Nan::New(inet_ntoa(lookup.sin_addr)).ToLocalChecked() );
		obj->Set(Nan::New("port").ToLocalChecked() , Nan::New(ntohs(lookup.sin_port)) );
	}
	
	info.GetReturnValue().Set(obj);
	
}



NAN_MODULE_INIT(init){
	Nan::Set(target, Nan::New("natLookup").ToLocalChecked(),Nan::GetFunction(Nan::New<FunctionTemplate>(natLookup)).ToLocalChecked());
	Nan::Set(target, Nan::New("natLookupSync").ToLocalChecked(),Nan::GetFunction(Nan::New<FunctionTemplate>(natLookupSync)).ToLocalChecked());
}

NODE_MODULE(natlookup, init);

