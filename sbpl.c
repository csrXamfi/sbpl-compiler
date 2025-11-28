//
//  main.c
//  sbpl
//
//  Created by mikhail on 28.11.2025.
//

#include <stdlib.h>
#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>
#include "sandbox.h"

int main(int argc, const char * argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s input_sb output_bin\n", argv[0]);
        return 1;
    }
    char *inputPath = realpath(argv[1], NULL);
    if (!inputPath) {
        perror("Failed to resolve input file path");
        return 1;
    }
    const char *outputPath = argv[2];
    char *error_msg = NULL;
    sbProfile_t *compiled_profile = sandbox_compile_file(inputPath, 0, &error_msg);
    if (!compiled_profile) {
        fprintf(stderr, "Failed to compile sandbox profile: %s\n", error_msg ? error_msg : "Unknown error");
        free(inputPath);
        return 1;
    }
    if (!compiled_profile->blob || compiled_profile->len <= 0) {
        fprintf(stderr, "Compiled profile is empty or invalid\n");
        free(inputPath);
        return 1;
    }
    FILE *outputFile = fopen(outputPath, "wb");
    if (!outputFile) {
        perror("Failed to open output file");
        free(inputPath);
        return 1;
    }
    size_t bytesWritten = fwrite(compiled_profile->blob, 1, compiled_profile->len, outputFile);
    if (bytesWritten != compiled_profile->len) {
        fprintf(stderr, "Failed to write all bytecode to output file (wrote %zu of %d bytes)\n",
                bytesWritten, compiled_profile->len);
        fclose(outputFile);
        free(inputPath);
        return 1;
    }
    printf("Successfully compiled %s -> %s (%d bytes)\n", inputPath, outputPath, compiled_profile->len);
    fclose(outputFile);
    free(inputPath);
    return EXIT_SUCCESS;
}

