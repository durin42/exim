#include <memory>
#include <string>
#include <stdlib.h>

#include <fuzzer/FuzzedDataProvider.h>

extern "C" {
#include "exim.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
        FuzzedDataProvider provider(Data, Size);
        std::string input = provider.ConsumeRemainingBytesAsString();
        uschar out[4096];
        parse_fix_phrase((uschar*)input.c_str(), input.size(), out, 4096);
        return 0; // Non-zero return values are reserved for future use.
}

} // extern "C"
