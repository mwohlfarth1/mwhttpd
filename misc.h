#ifndef MISC_H
#define MISC_H

#include <stddef.h>

char *get_content_type(char *filename);

typedef struct {
  char *display_name;
  char *url;
} file_link;

char *generate_dir_listing(char *dir_name, int num_files, file_link *files);
unsigned char * base64_encode(const unsigned char *src, size_t len,
                              size_t *out_len);


#endif // MISC_H
