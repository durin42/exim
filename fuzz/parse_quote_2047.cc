#include <memory>
#include <string>
#include <stdlib.h>

#include <fuzzer/FuzzedDataProvider.h>

extern "C" {
#include "exim.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
        FuzzedDataProvider provider(Data, Size);
        bool fold = provider.ConsumeBool();
        std::string charset = provider.ConsumeRandomLengthString(32);
        std::string input = provider.ConsumeRemainingBytesAsString();
        uschar out[4096];
        parse_quote_2047((uschar*) input.c_str(),
                           input.size(),
                           (uschar*) charset.c_str(),
                           out,
                           sizeof(out),
                           fold);

        return 0; // Non-zero return values are reserved for future use.
}

} // extern "C"
