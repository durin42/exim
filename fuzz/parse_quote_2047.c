#include <stdlib.h>

#include "fdp.h"

#include "exim.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
        bool fold = ConsumeBool(&Data, &Size);
        char* charset = ConsumeRandomLengthNullTerminatedString(&Data, &Size,
                                                                32);
        size_t input_size = Size;
        char* input = ConsumeNullTerminatedString(&Data, &Size);
        uschar out[4096];
        parse_quote_2047((uschar*) input,
                         input_size,
                         (uschar*) charset,
                           out,
                           sizeof(out),
                           fold);

        free(charset);
        free(input);
        return 0; // Non-zero return values are reserved for future use.
}
