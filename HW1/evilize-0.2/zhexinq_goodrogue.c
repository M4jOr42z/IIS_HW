/* zhexinq's good/rogue executables with same MD5 hash */

#include <stdio.h>
#include <unistd.h>

/* do something innocent */
int main_good(int ac, char *av[]) {
  char buf[10];
  fprintf(stdout, "Hello, I am innocent!\n");
  fprintf(stdout, "\n(press enter to quit)");
  fflush(stdout);
  fgets(buf, 10, stdin);
  return 0;
}

/* do something evil */
int main_evil(int ac, char *av[]) {
  char buf[10];
  fprintf(stdout, "AHaaaah, I am rogue!!!\n");
  fprintf(stdout, "Searching your shopping accounts");
  fflush(stdout);
  sleep(1);
  fprintf(stdout, "found 1...");
  fflush(stdout);
  sleep(1);
  fprintf(stdout, "start ording random items cost more than $1000");
  fflush(stdout);
  sleep(1);
  fprintf(stdout, " just kidding!\nNothing was hacked.\n");
  fprintf(stdout, "\n(press enter to quit)");
  fflush(stdout);
  fgets(buf, 10, stdin);
  return 0;
}
