#ifndef CLICK_PATH_HH
#define CLICK_PATH_HH
#include <click/straccum.hh>
CLICK_DECLS

typedef Vector<IPAddress> Path;


inline unsigned
hashcode(const Path &p)
{
  unsigned h = 0;
  for (int x = 0; x < p.size(); x++) {
    h = h ^ hashcode(p[x]);
  }
  return h;
}

inline bool
operator==(const Path &p1, const Path &p2)
{
  if (p1.size() != p2.size()) {
    return false;
  }
  for (int x = 0; x < p1.size(); x++) {
    if (p1[x] != p2[x]) {
      return false;
    }
  }
  return true;
}

inline String path_to_string(const Path &p) 
{
  StringAccum sa;
  for(int x = 0; x < p.size(); x++) {
    sa << p[x].s().cc();
    if (x != p.size() - 1) {
      sa << " ";
    }
  }
  return sa.take_string();
}


inline Path reverse_path (const Path &p) 
{
  Path rev;
  for (int x = p.size() - 1; x >= 0; x--) {
    rev.push_back(p[x]);
  }
  return rev;
}


CLICK_ENDDECLS
#endif /* CLICK_PATH_HH */
