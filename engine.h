#include <fl/Headers.h>
#include "mongoose.h"

extern "C" {
	const mbuf* decode_msgpack(mbuf* buffer, int len);
	const mbuf* decode_json(mbuf* buffer, int len);
	mbuf* str_to_mbuf(const std::string& str);

	const mg_str decode_json_str(mg_str* buffer);

	std::vector<fl::scalar> engine_output_state(fl::Engine* engine);
	fl::Engine* load_engine();
}