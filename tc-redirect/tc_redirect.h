#ifndef __TC_REDIRECT_H__
#define __TC_REDIRECT_H__

#define LO_IFINDEX      1

#define MAX_PAYLOAD     1514

struct data_event {
    __u32 len;
    __u8 data[MAX_PAYLOAD];
};

#endif // __TC_REDIRECT_H__
