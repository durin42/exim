#include <memory>
#include <string>
#include <stdlib.h>

#include <fuzzer/FuzzedDataProvider.h>

extern "C" {
#include "exim.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
        FuzzedDataProvider provider(Data, Size);
        bool allow_null_address = provider.ConsumeBool();
        std::string mbox = provider.ConsumeRemainingBytesAsString();
        uschar *errorptr;
        int start, end, domain;
        parse_extract_address((uschar*)mbox.c_str(), &errorptr, &start, &end, &domain, allow_null_address);
	return 0; // Non-zero return values are reserved for future use.
}

} // extern "C"
