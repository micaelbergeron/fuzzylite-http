#include <iostream>
#include <iterator>

#include "engine.h"
#include "msgpack11.hpp"
#include "picojson.h"

// -- TCP SERVER
extern "C" {

    static void tcp_ev_handler(struct mg_connection *nc, int ev, void *p) {
        struct mbuf *io = &nc->recv_mbuf;
        const mbuf *decode_buf;

        // decode the msgpack stream
        switch (ev) {
            case MG_EV_RECV:
                decode_buf = decode_json(io, io->len);
                //mg_send(nc, io->buf, io->len); // Echo
                mg_send(nc, decode_buf->buf, decode_buf->len);
                mbuf_remove(io, io->len); // Discard message from recv buffer
                mbuf_free((mbuf*) decode_buf);
                break;
            default:
                break;
        }
    }

    int tcp_server(void) {
        struct mg_mgr mgr;
        const char *port1 = "1234", *port2 = "127.0.0.1:17000";

        mg_mgr_init(&mgr, NULL);
        mg_bind(&mgr, port1, tcp_ev_handler);
        mg_bind(&mgr, port2, tcp_ev_handler);

        printf("Starting echo mgr on ports %s, %s\n", port1, port2);
        for (;;) {
            mg_mgr_poll(&mgr, 1000);
        }
        mg_mgr_free(&mgr);

        return 0;
    }

}
// -- TCP SERVER

// -- HTTP SERVER
extern "C" {
    static const char *s_http_port = "8000";
    static struct mg_serve_http_opts s_http_server_opts;

    static void handle_api_call(struct mg_connection *nc, struct http_message *hm) {
        mg_str json_response = decode_json_str(&hm->body);

        /* Send headers */
        mg_printf(nc, "%s", "HTTP/1.1 200 OK\r\n");
        mg_printf(nc, "Content-type: %s\r\n", "application/json");
        mg_printf(nc, "Content-length: %d\r\n", (int) json_response.len);
        mg_printf(nc, "Access-Control-Allow-Origin: %s\r\n", "*");
        mg_printf(nc, "Access-Control-Allow-Headers: %s\r\n", "content-type");
        mg_printf(nc, "Access-Control-Allow-Methods: %s\r\n", "POST, OPTIONS");
        mg_printf(nc, "\r\n");

        /* Compute the result and send it back as a JSON object */
        mg_printf(nc, json_response.p, json_response.len);
    }

    static void http_ev_handler(struct mg_connection *nc, int ev, void *ev_data) {
        struct http_message *hm = (struct http_message *) ev_data;

        switch (ev) {
            case MG_EV_HTTP_REQUEST:
                if (mg_vcmp(&hm->uri, "/api/pathology") == 0) {
                    handle_api_call(nc, hm); /* Handle RESTful call */
                } else if (mg_vcmp(&hm->uri, "/printcontent") == 0) {
                    char buf[100] = {0};
                    memcpy(buf, hm->body.p,
                            sizeof (buf) - 1 < hm->body.len ? sizeof (buf) - 1 : hm->body.len);
                    printf("%s\n", buf);
                    mg_printf(nc, "%s", "HTTP/1.1 200 OK\r\n");
                    mg_printf(nc, "Transfer-Encoding: %s", "chunked\r\n");
                    mg_printf(nc, "\r\n");
                    mg_send_http_chunk(nc, "", 0); /* Send empty chunk, the end of response */
                }
                break;
            default:
                break;
        }
    }

    int http_server(int argc, char *argv[]) {
        struct mg_mgr mgr;
        struct mg_connection *nc;
        struct mg_bind_opts bind_opts;
        int i;
        char *cp;
        const char *err_str;

        mg_mgr_init(&mgr, NULL);

        /* Use current binary directory as document root */
        if (argc > 0 && ((cp = strrchr(argv[0], DIRSEP)) != NULL)) {
            *cp = '\0';
            s_http_server_opts.document_root = argv[0];
        }

        /* Process command line options to customize HTTP server */
        for (i = 1; i < argc; i++) {
            if (strcmp(argv[i], "-D") == 0 && i + 1 < argc) {
                mgr.hexdump_file = argv[++i];
            } else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
                s_http_server_opts.document_root = argv[++i];
            } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
                s_http_port = argv[++i];
            } else if (strcmp(argv[i], "-a") == 0 && i + 1 < argc) {
                s_http_server_opts.auth_domain = argv[++i];
            } else if (strcmp(argv[i], "-r") == 0 && i + 1 < argc) {
                s_http_server_opts.url_rewrites = argv[++i];
            }
        }

        /* Set HTTP server options */
        memset(&bind_opts, 0, sizeof (bind_opts));
        bind_opts.error_string = &err_str;

        nc = mg_bind_opt(&mgr, s_http_port, http_ev_handler, bind_opts);
        if (nc == NULL) {
            fprintf(stderr, "Error starting server on port %s: %s\n", s_http_port,
                    *bind_opts.error_string);
            exit(1);
        }

        mg_set_protocol_http_websocket(nc);
        s_http_server_opts.enable_directory_listing = "no";

        printf("Starting RESTful server on port %s, serving %s\n",
                s_http_port,
                s_http_server_opts.document_root);

        for (;;) {
            mg_mgr_poll(&mgr, 1000);
        }

        mg_mgr_free(&mgr);

        return 0;
    }
}
// -- HTTP SERVER

const mbuf* decode_msgpack(mbuf* buffer, int len) {
    msgpack11::MsgPack::array a{ 0, 1, 2, 3, 4};
    msgpack11::MsgPack packed{ a};
    std::string dump = packed.dump();

    mbuf* obuf = new mbuf;
    mbuf_init(obuf, dump.length());
    mbuf_append(obuf, dump.data(), dump.length());
    return obuf;
}

const mbuf* decode_json(mbuf* buffer, int len) {
    typedef picojson::value _v;
    auto json_raw = std::string(buffer->buf, len);

    picojson::value json_request;
    ;
    std::string err = picojson::parse(json_request, json_raw);
    if (!err.empty()) {
        std::cerr << "PicoJSON error: " << err << std::endl;
        return str_to_mbuf(err);
    }

    if (!json_request.is<picojson::object>()) {
        std::cerr << "Input is not a JSON Object." << std::endl;
        return buffer;
    }

    picojson::array outputs = picojson::array();

    // fill the engine
    fl::Engine* r_engine = load_engine();

    const picojson::value::object& input_map = json_request.get<picojson::object>();
    for (auto it = input_map.begin();
            it != input_map.end();
            ++it) {
        if (!r_engine->hasInputVariable(it->first)) {
            std::cerr << "Input variable not found: " << it->first << ", skipping." << std::endl;
            continue;
        }

        r_engine->setInputValue(it->first, it->second.get<fl::scalar>());
    }
    r_engine->process();

    // TODO: add the name of the output
    const std::vector<fl::OutputVariable*>& state = r_engine->outputVariables();
    for (auto it = state.begin();
            it != state.end();
            ++it) {
        fl::scalar output = (*it)->getValue();
        if (std::isnan(output)) output = 0;
        outputs.push_back(_v(output));
    }

    free(r_engine);

    // output this
    std::stringstream dump;
    dump << _v(outputs).serialize() << std::endl;

    //std::string dump = json_request.serialize();
    return str_to_mbuf(dump.str());
}

const mg_str decode_json_str(mg_str* buffer) {
    mbuf raw = mbuf();
    mbuf_init(&raw, buffer->len);
    mbuf_append(&raw, buffer->p, buffer->len);
    const mbuf* decoded = decode_json(&raw, raw.len);
    return mg_mk_str_n(decoded->buf, decoded->len);
}

// Copy the std::string to a mbuf and return a pointer to it.

mbuf* str_to_mbuf(const std::string& str) {
    const int olen = str.length();

    mbuf* obuf = new mbuf;
    mbuf_init(obuf, olen);
    obuf->len = olen;
    memcpy(obuf->buf, str.data(), olen);
    return obuf;
}

fl::Engine* engine_prototype = nullptr;
std::string rules_path;

fl::Engine* load_engine() {
    if (engine_prototype == nullptr) {
        engine_prototype = fl::FllImporter().fromFile(rules_path);
    }

    return new fl::Engine(*engine_prototype);
}

int usage(char** argv) {
    std::cout << "FLL Rules must be provided: " << argv[0] << " rules.fll" << std::endl;
    return -1;
}

int main(int argc, char** argv) {
    if (argc < 2) return usage(argv);

    rules_path = std::string(argv[1]);
    int status = http_server(argc, argv);

    free(engine_prototype);
    return status;
}
