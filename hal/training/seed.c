#include <libcgc.h>

typedef char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef long long int64_t;
typedef unsigned long long uint64_t;


size_t receive_until(int fd, char *dst, char delim, size_t max )
{
    size_t len = 0;
    size_t rx = 0;
    char c = 0;

    while( len < max ) {
        dst[len] = 0x00;

        if ( receive( fd, &c, 1, &rx ) != 0 ) {
            len = 0;
            goto end;
        }

        if ( c == delim ) {
            goto end;
        }
   
        dst[len] = c;
        len++;
    }
end:
    return len;
}

size_t receive_n( int fd, char *dst, size_t n_bytes )
{
  size_t len = 0;
  size_t rx = 0;
  while(len < n_bytes) {
    if (receive(fd, dst + len, n_bytes - len, &rx) != 0) {
      len = 0;
      break;
    }
    len += rx;
  }

  return len;
}

int send_all(int fd, const void *msg, size_t n_bytes)
{
  size_t len = 0;
  size_t tx = 0;
  while(len < n_bytes) {
    if (transmit(fd, (char *)msg + len, n_bytes - len, &tx) != 0) {
      return 1;
    }
    len += tx;
  }
  return 0;
}

int strlen(char *s)
{
	int i = 0;
	while (s[i]) i++;
	return i;
}

void puts(char *s)
{
	send_all(1, s, strlen(s));
	send_all(1, "\n", 1);
}

void puts_nonewline(char *s)
{
	send_all(1, s, strlen(s));
}

void bzero(char *s, int n)
{
	while (n > 0) s[--n] = 0;
}

int count_ones(char *what, int n)
{
	int count = 0;
	while (n > 0) if (what[--n]) count++;
	return count;
}

void print_epilogue()
{
	puts("");
	puts("Good job! Check the function countdown on the left; you should be ready.");
	puts("to collect payment!");
	puts("");
	puts("You might have noticed that we color the application's output to help.");
	puts("differentiate it from your input, if you need to look back to see what");
	puts("you've entered so far.");
	puts("");
	puts("To trigger all functionality in this application, you need to make sure");
	puts("to provide all of the different types of inputs that it might expect.");
	puts("While this application is simple, other applications might be more complex.");
	puts("For example, you will encounter video games and chat software. In those");
	puts("applications, you might need to win games and solve problems to trigger");
	puts("functionality.");
	puts("");
	puts("Sometimes, software might crash of freeze. In these cases, you can click");
	puts("\"Reset VM\" on the left of the page to restart the program. The software");
	puts("will restart. While your progress (on the left) will be remembered, the software");
	puts("itself will not remember your previous input. You can use this to get a \"fresh");
	puts("start\" for triggering different functions than you triggered last time. However,");
	puts("but keep in mind that re-triggering functions that you triggered *before*");
	puts("restarting will not count toward your score a second time; you will have to");
	puts("trigger *new* functions!");
}

void print_one()
{
	puts("Good job! You've triggered the function that handles the first menu item.");
}

void print_two()
{
	puts("Awesome! You've triggered the function that handles the second menu item.");
}

int do_three()
{
	char input[100];
	puts_nonewline("> ");
	receive_until(0, input, '\n', 6);
	if (input[0] == '4' || (input[0] == 'f' && input[1] == 'o')) return 1;
	else
	{
		return 0;
	}
}

int main()
{
	char input[100];
	input[0] = '\0';
	size_t rx;

	puts("##################### Welcome to the training exercise.");
	puts("");
	puts("In this training exercise, we will go through the basics of how to interact");
	puts("with this software for our series of HITs.");
	puts("");
	puts("Software is made up of functions. These functions do different things, and in");
	puts("order to take action, software executes the appropriate functions for those");
	puts("actions.");
	puts("");
	puts("Of course, the software executes these functions in response to user input.");
	puts("In this case, you are the user. For these HITs, we are interested in triggering");
	puts("the execution of as many functions as possible, for the purposes of software");
	puts("testing. Your task, in these HITs, is to provide input to the software to");
	puts("trigger it to do this.");
	puts("");
	puts("On the left, you should see information about your progress toward this goal.");
	puts("That information is:");
	puts("");
	puts("- Total functions: the total number of functions in this software.");
	puts("- Triggered by previous HITs: the number of functions that have already been");
	puts("                              triggered by other HITs. Causing these to be");
	puts("                              executed will not count toward your goal.");
	puts("- Remaining to payout: this is the minimum number of functions you must trigger");
	puts("                     to collect payment");
	puts("- Next Bonus Target: after you trigger the necessary number of functions, work");
	puts("                     begins toward your bonus! The number of functions necessary");
	puts("                     for the next bonus is displayed here.");
	puts("- Payout information: this shows the pay that you will receive if you hit Submit");
	puts("                      now, and what you would receive after the next bonus.");
	puts("");
	puts("As you interact with the software and more functions are triggered, the remaining");
	puts("number will decrease. When it hits zero, you may submit the task for the minimum");
	puts("payment, or keep triggering new functions to earn payment bonuses.");
	puts("");
	puts("As an example, this software will now wait for you to hit Enter. Doing this will");
	puts("trigger the execution of several functions. Please press enter and notice how the");
	puts("progress numbers on the left change.");
	puts("");
	puts_nonewline("Please press enter now >");

    	if (receive(0, input, 1, &rx) || !rx)
	{
		_terminate(1);
	}

	if (input[0] != '\n')
	{
		puts("You triggered an easter-egg in the program by inputting something");
		puts("unexpected! In this case, it expected you to hit Enter, but you");
		puts("typed some other letters first. This sort of trickery is very useful");
		puts("for triggering functions in software -- it's a good skill!");
		puts("");
		receive_until(0, input, '\n', 99);
	}

	puts("");
	puts("Great job! Notice how the remaining required number of functions has decreased.");
	puts("Next, we will walk through some functionality that you might commonly encounter");
	puts("in these HITs. As you interact with this software, keep an eye on how much the");
	puts("numbers on the left change.");
	puts("");
	puts("A common thing you will encounter are menus. These are great for triggering many");
	puts("functions, since each option is usually handled by a different function. Below is");
	puts("an example menu. Try to trigger all of its actions!");

	int one_triggered = 0;
	int two_triggered = 0;
	int three_triggered = 0;
	while (one_triggered + two_triggered + three_triggered < 3)
	{
		puts("");
		puts("Please choose an option below:");
		puts("");
		puts("1. First menu option.");
		if (one_triggered) puts("... triggered!");
		puts("2. First menu option.");
		if (two_triggered) puts("... triggered!");
		puts("3. First menu option.");
		if (three_triggered) puts("... triggered!");
		puts("");
		puts_nonewline("Choice: ");
		receive_until(0, input, '\n', 99);

		switch (input[0])
		{
			case '1':
				one_triggered++;
				print_one();
				one_triggered = 1;
				break;
			case '2':
				two_triggered++;
				print_two();
				two_triggered = 1;
				break;
			case '3':
				puts("A-ha! The third menu item is tricky. To trigger it, please answer this:");
				puts("QUESTION: what is the number between 3 and 5?");
				if (do_three()) three_triggered = 1;
				else puts("Incorrect...");
				break;
			default:
				puts("Please enter 1, 2, or 3...");
				break;
		}
	}

	print_epilogue();
	puts("");
	puts("Here is the password to complete the qualification task: 956322392501613680");

  	return 0;
}


