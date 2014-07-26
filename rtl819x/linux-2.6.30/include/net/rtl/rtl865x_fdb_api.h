
#ifndef RTL865X_FDB_API_H
#define RTL865X_FDB_API_H
void update_hw_l2table(const char *srcName,const unsigned char *addr);
int32 rtl_get_hw_fdb_age(uint32 fid,ether_addr_t *mac, uint32 flags);

#endif
