#include <memory>
#include <string>
#include <stdlib.h>

#include <fuzzer/FuzzedDataProvider.h>

extern "C" {
#include "exim.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
        FuzzedDataProvider provider(Data, Size);
        int options = 0;
        if (provider.ConsumeBool()) {
          options |= RDO_DEFER;
        }
        if (provider.ConsumeBool()) {
          options |= RDO_FREEZE;
        }
        if (provider.ConsumeBool()) {
          options |= RDO_FAIL;
        }
        if (provider.ConsumeBool()) {
          options |= RDO_BLACKHOLE;
        }
        if (provider.ConsumeBool()) {
          options |= RDO_REWRITE;
        }
        if (provider.ConsumeBool()) {
          options |= RDO_INCLUDE;
        }
        address_item *anchor = NULL;
        uschar *error = NULL;
        std::string incoming_domain = provider.ConsumeRandomLengthString(32);
        std::string input = provider.ConsumeRemainingBytesAsString();
        parse_forward_list((uschar*) input.c_str(),
                           options,
                           &anchor,
                           &error,
                           (uschar*) incoming_domain.c_str(),
                           NULL,
                           NULL);

        return 0; // Non-zero return values are reserved for future use.
}

} // extern "C"
