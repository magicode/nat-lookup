
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
	uv_work_t request;
	Persistent<Function> callback;

	struct sockaddr_in lookup;
	int fd;
	bool success;
	int errnum;
	//struct natlookup natLookup;
};

static void DetectWork(uv_work_t* req) {

	Baton* baton = static_cast<Baton*>(req->data);

	socklen_t len = sizeof(struct sockaddr_in);
	printf("start nlp %d\n" , baton->fd);
	if (getsockopt(baton->fd, SOL_IP, SO_ORIGINAL_DST, &baton->lookup, &len) != 0){
		baton->success = false;
		baton->errnum = errno;
	} else {
		baton->success = true;
	}
	printf("end nlp %d\n" , baton->fd);
}

static void DetectAfter(uv_work_t* req) {
	HandleScope scope;
	Baton* baton = static_cast<Baton*>(req->data);

	if (baton->success) {

		const unsigned argc = 3;
		Local<Value> argv[argc] = {
			Local<Value>::New(Null()),
			Local<Value>::New(String::New(inet_ntoa(baton->lookup.sin_addr))),
			Local<Value>::New(Integer::New(ntohs(baton->lookup.sin_port))),
		};

		TryCatch try_catch;
		baton->callback->Call(Context::GetCurrent()->Global(), argc, argv);
		if (try_catch.HasCaught())
			FatalException(try_catch);
	} else {

		Local<Value> err ;

		if(baton->errnum != 0)
			err = Exception::Error(String::New(strerror(baton->errnum)));
		else
			err = Exception::Error(String::New("error"));


		const unsigned argc = 1;
		Local<Value> argv[argc] = {err};

		TryCatch try_catch;
		baton->callback->Call(Context::GetCurrent()->Global(), argc, argv);
		if (try_catch.HasCaught())
			FatalException(try_catch);
	}

	baton->callback.Dispose();
	delete baton;
}



static Handle<Value> natLookup(const Arguments& args) {
	HandleScope scope;

	if (args.Length() < 4) {
		return ThrowException(
				Exception::TypeError(String::New("Expecting 4 arguments")));
	}

	if (!args[3]->IsFunction()) {
		return ThrowException(
				Exception::TypeError(
						String::New(
								"4 argument must be a callback function")));
	}

	Local<Function> callback = Local<Function>::Cast(args[3]);

	Baton* baton = new Baton();
	baton->request.data = baton;
	baton->callback = Persistent < Function > ::New(callback);
	baton->success = false;
	baton->errnum = 0;

	memset(&baton->lookup, 0, sizeof(baton->lookup));


	baton->fd = args[0]->IntegerValue();
	baton->lookup.sin_port = htons((u_short)args[1]->IntegerValue());
	baton->lookup.sin_addr.s_addr = inet_addr((const char*)(* String::AsciiValue( args[2]->ToString()) ));



	int status = uv_queue_work(uv_default_loop(),
	&baton->request,
	DetectWork,
	(uv_after_work_cb)DetectAfter);

	assert(status == 0);
	return Undefined();

}


extern "C" {
	void init(Handle<Object> target) {
		HandleScope scope;
		target->Set(String::NewSymbol("natLookup"),
								FunctionTemplate::New(natLookup)->GetFunction());
	}

	NODE_MODULE(natlookup, init);
}
