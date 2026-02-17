/*****************************************************************************
*
* Nagios check_snmp plugin
*
* License: GPL
* Copyright (c) 1999-2018 Nagios Plugins Development Team
*
* Description:
*
* This file contains the check_snmp plugin
*
* Check status of remote machines and obtain system information via SNMP
*
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*
*
*****************************************************************************/

const char *progname = "check_snmp";
const char *copyright = "1999-2018";
const char *email = "devel@nagios-plugins.org";

#include "common.h"
#include "runcmd.h"
#include "utils.h"
#include "utils_cmd.h"
#include <sys/stat.h>
#include <unistd.h>
#include <sqlite3.h>

#ifndef LOCALEDIR
#define LOCALEDIR "/usr/local/nagios/share/locale"
#endif

#define DEFAULT_COMMUNITY "public"
#define DEFAULT_PORT "161"
#define DEFAULT_MIBLIST "ALL"
#define DEFAULT_PROTOCOL "1"
#define DEFAULT_RETRIES 5
#define DEFAULT_AUTH_PROTOCOL "MD5"
#define DEFAULT_PRIV_PROTOCOL "DES"
#define DEFAULT_DELIMITER "="
#define DEFAULT_OUTPUT_DELIMITER " "

#define mark(a) ((a)!=0?"*":"")

#define CHECK_UNDEF 0
#define CRIT_PRESENT 1
#define CRIT_STRING 2
#define CRIT_REGEX 4
#define WARN_PRESENT 8
#define WARN_STRING 16
#define WARN_REGEX 32

#define OID_COUNT_STEP 8

/* Longopts only arguments */
#define L_CALCULATE_RATE CHAR_MAX+1
#define L_RATE_MULTIPLIER CHAR_MAX+2
#define L_INVERT_SEARCH CHAR_MAX+3
#define L_OFFSET CHAR_MAX+4
#define STRICT_MODE CHAR_MAX+5
#define L_MULTIPLIER CHAR_MAX+6
#define L_THROUGHPUT CHAR_MAX+7
#define L_STATUS CHAR_MAX+9
#define L_COUNTER_BITS CHAR_MAX+10
#define L_DB_KEY CHAR_MAX+11

/* Gobble to string - stop incrementing c when c[0] match one of the
 * characters in s */
#define GOBBLE_TOS(c, s) while(c[0]!='\0' && strchr(s, c[0])==NULL) { c++; }
/* Given c, keep track of backslashes (bk) and double-quotes (dq)
 * from c[0] */
#define COUNT_SEQ(c, bk, dq) switch(c[0]) {\
	case '\\': \
		if (bk) bk--; \
		else bk++; \
		break; \
	case '"': \
		if (!dq) { dq++; } \
		else if(!bk) { dq--; } \
		else { bk--; } \
		break; \
	}



int process_arguments (int, char **);
int validate_arguments (void);
char *thisarg (char *str);
char *nextarg (char *str);
void print_usage (void);
void print_help (void);

#include "regex.h"
#include <ctype.h>
char regex_expect[MAX_INPUT_BUFFER] = "";
regex_t preg;
regmatch_t pmatch[10];
char errbuf[MAX_INPUT_BUFFER] = "";
char perfstr[MAX_INPUT_BUFFER] = "| ";
int cflags = REG_EXTENDED | REG_NOSUB | REG_NEWLINE;
int eflags = 0;
int errcode, excode;

char *server_address = NULL;
char *community = NULL;
char **contextargs = NULL;
char *context = NULL;
char **authpriv = NULL;
char *proto = NULL;
char *seclevel = NULL;
char *secname = NULL;
char *authproto = NULL;
char *privproto = NULL;
char *authpasswd = NULL;
char *privpasswd = NULL;
char **oids = NULL;
size_t oids_size = 0;
char *label;
char *units;
char *port;
char *snmpcmd;
char string_value[MAX_INPUT_BUFFER] = "";
int  invert_search=0;
char **labels = NULL;
char **unitv = NULL;
size_t nlabels = 0;
size_t labels_size = OID_COUNT_STEP;
size_t nunits = 0;
size_t unitv_size = OID_COUNT_STEP;
int numoids = 0;
int numauthpriv = 0;
int numcontext = 0;
int verbose = 0;
int usesnmpgetnext = FALSE;
char *warning_thresholds = NULL;
char *critical_thresholds = NULL;
thresholds **thlds;
size_t thlds_size = OID_COUNT_STEP;
double *response_value;
size_t response_size = OID_COUNT_STEP;
int retries = 0;
int *eval_method;
size_t eval_size = OID_COUNT_STEP;
char *delimiter;
char *output_delim;
char *miblist = NULL;
int needmibs = FALSE;
int calculate_rate = 0;
static int strict_mode = 0;
double offset = 0.0;
double multiplier = 1.0;
int rate_multiplier = 1;
state_data *previous_state;
double *previous_value;
size_t previous_size = OID_COUNT_STEP;
int perf_labels = 1;
char* ip_version = "";

int check_throughput = 0;
int check_status = 0;
char *db_path = NULL;
char *interface_idx = NULL;
char *db_key = NULL;
char *status_oid = NULL;
int explicit_counter_bits = 0;

typedef struct {
	time_t timestamp;
	unsigned long long in_octets;
	unsigned long long out_octets;
	int counter_bits; 
} OctetData;

/* Prototypes for throughput helpers */
const char *determine_db_path(void);
int validate_db_key(const char *key);
int db_read_state(const char *db_path, const char *host, const char *iface, OctetData *data);
int db_write_state(const char *db_path, const char *host, const char *iface, const OctetData *data);
unsigned long long calculate_wraparound(unsigned long long current, unsigned long long previous, int counter_bits);
double calculate_throughput(unsigned long long octet_diff, time_t time_diff, const char *unit);
double convert_throughput(double value, const char *unit, int to_unit);

static char *fix_snmp_range(char *th)
{
	double left, right;
	char *colon, *ret;

	if ((colon = strchr(th, ':')) == NULL || *(colon + 1) == '\0')
		return th;

	left = strtod(th, NULL);
	right = strtod(colon + 1, NULL);
	if (right >= left)
		return th;

	if ((ret = malloc(strlen(th) + 2)) == NULL)
		die(STATE_UNKNOWN, _("Cannot malloc"));
	*colon = '\0';
	sprintf(ret, "@%s:%s", colon + 1, th);
	free(th);
	return ret;
}

int
main (int argc, char **argv)
{
	int i, j, len, line, total_oids;
	unsigned int bk_count = 0, dq_count = 0;
	int iresult = STATE_UNKNOWN;
	int result = STATE_UNKNOWN;
	int return_code = 0;
	int external_error = 0;
	char **command_line = NULL;
	char *cl_hidden_auth = NULL;
	char *oidname = NULL;
	char *response = NULL;
	char *mult_resp = NULL;
	char *outbuff;
	char *ptr = NULL;
	char *show = NULL;
	char *th_warn=NULL;
	char *th_crit=NULL;
	char type[8] = "";
	output chld_out, chld_err;
	char *previous_string=NULL;
	char *ap=NULL;
	char *state_string=NULL;
	size_t response_length, current_length, string_length, show_length;
	char *temp_string=NULL;
	char *quote_string=NULL;
	time_t current_time;
	double temp_double;
	time_t duration;
	char *conv = "12345678";
	int is_counter=0;
	int command_interval;
	int is_ticks= 0;

	setlocale (LC_ALL, "");
	bindtextdomain (PACKAGE, LOCALEDIR);
	textdomain (PACKAGE);

	labels = malloc (labels_size * sizeof(*labels));
	unitv = malloc (unitv_size * sizeof(*unitv));
	thlds = malloc (thlds_size * sizeof(*thlds));
	response_value = malloc (response_size * sizeof(*response_value));
	previous_value = malloc (previous_size * sizeof(*previous_value));
	eval_method = calloc (eval_size, sizeof(*eval_method));
	oids = calloc(oids_size, sizeof (char *));

	label = strdup ("SNMP");
	units = strdup ("");
	port = strdup (DEFAULT_PORT);
	outbuff = strdup ("");
	delimiter = strdup (" = ");
	output_delim = strdup (DEFAULT_OUTPUT_DELIMITER);
	retries = DEFAULT_RETRIES;

	np_init( (char *) progname, argc, argv );

	/* Parse extra opts if any */
	argv=np_extra_opts (&argc, argv, progname);

	np_set_args(argc, argv);

	time(&current_time);

	if (process_arguments (argc, argv) == ERROR)
		usage4 (_("Could not parse arguments"));

	db_path = (char *)determine_db_path();

	command_interval = timeout_interval / retries + 1;
	if (command_interval < 1) {
		usage4 (_("Command timeout must be 1 second or greater. Please increase timeout (-t) value or decrease retries (-e) value."));
		exit (STATE_UNKNOWN);
	}

	if(calculate_rate && !check_throughput) {
		if (!strcmp(label, "SNMP"))
			label = strdup("SNMP RATE");
		i=0;
		previous_state = np_state_read();
		if(previous_state!=NULL) {
			/* Split colon separated values */
			previous_string = strdup((char *) previous_state->data);
			while((ap = strsep(&previous_string, ":")) != NULL) {
				if(verbose>2)
					printf("Previous State for %d=%s\n", i, ap);
				while (i >= previous_size) {
					previous_size += OID_COUNT_STEP;
					previous_value = realloc(previous_value, previous_size * sizeof(*previous_value));
				}
				previous_value[i++]=strtod(ap,NULL);
			}
		}
	}


	/* Populate the thresholds */
	th_warn=warning_thresholds;
	th_crit=critical_thresholds;
	for (i=0; i<numoids; i++) {
		char *w = th_warn ? strndup(th_warn, strcspn(th_warn, ",")) : NULL;
		char *c = th_crit ? strndup(th_crit, strcspn(th_crit, ",")) : NULL;
		/* translate "2:1" to "@1:2" for backwards compatibility */
		w = w ? fix_snmp_range(w) : NULL;
		c = c ? fix_snmp_range(c) : NULL;

		while (i >= thlds_size) {
			thlds_size += OID_COUNT_STEP;
			thlds = realloc(thlds, thlds_size * sizeof(*thlds));
		}

		/* Skip empty thresholds, while avoiding segfault */
		set_thresholds(&thlds[i],
		               w ? strpbrk(w, NP_THRESHOLDS_CHARS) : NULL,
		               c ? strpbrk(c, NP_THRESHOLDS_CHARS) : NULL);

		if (w) {
			th_warn=strchr(th_warn, ',');
			if (th_warn) th_warn++;
			free(w);
		}
		if (c) {
			th_crit=strchr(th_crit, ',');
			if (th_crit) th_crit++;
			free(c);
		}
	}

	/* Create the command array to execute */
	if(usesnmpgetnext == TRUE) {
		snmpcmd = strdup (PATH_TO_SNMPGETNEXT);
	}else{
		snmpcmd = strdup (PATH_TO_SNMPGET);
	}

	/* 10 arguments to pass before context and authpriv options + 1 for host and numoids. Add one for terminating NULL */
	command_line = calloc (10 + numcontext + numauthpriv + 1 + numoids + 1, sizeof (char *));
	command_line[0] = snmpcmd;
	command_line[1] = strdup ("-Le");
	command_line[2] = strdup ("-t");
	xasprintf (&command_line[3], "%d", command_interval);
	command_line[4] = strdup ("-r");
	xasprintf (&command_line[5], "%d", retries);
	command_line[6] = strdup ("-m");
	command_line[7] = strdup (miblist);
	command_line[8] = "-v";
	command_line[9] = strdup (proto);

	for (i = 0; i < numcontext; i++) {
		command_line[10 + i] = contextargs[i];
	}
	
	for (i = 0; i < numauthpriv; i++) {
		command_line[10 + numcontext + i] = authpriv[i];
	}

	xasprintf (&command_line[10 + numcontext + numauthpriv], "%s:%s", server_address, port);

	/* This is just for display purposes, so it can remain a string */
	xasprintf(&cl_hidden_auth, "%s -Le -t %d -r %d -m %s -v %s %s %s %s:%s",
		snmpcmd, command_interval, retries, strlen(miblist) ? miblist : "''", proto, "[context]", "[authpriv]",
		server_address, port);

	for (i = 0; i < numoids; i++) {
		command_line[10 + numcontext + numauthpriv + 1 + i] = oids[i];
		xasprintf(&cl_hidden_auth, "%s %s", cl_hidden_auth, oids[i]);	
	}

	command_line[10 + numcontext + numauthpriv + 1 + numoids] = NULL;

	if (verbose)
		printf ("%s\n", cl_hidden_auth);

	/* Set signal handling and alarm */
	if (signal (SIGALRM, runcmd_timeout_alarm_handler) == SIG_ERR) {
		usage4 (_("Cannot catch SIGALRM"));
	}
	alarm(timeout_interval + 1);

	/* Run the command */
	return_code = cmd_run_array (command_line, &chld_out, &chld_err, 0);

	/* disable alarm again */
	alarm(0);

	/* Due to net-snmp sometimes showing stderr messages with poorly formed MIBs,
	   only return state unknown if return code is non zero or there is no stdout.
	   Do this way so that if there is stderr, will get added to output, which helps problem diagnosis
	*/
	if (return_code != 0)
		external_error=1;
	if (chld_out.lines == 0)
		external_error=1;
	if (external_error) {
		if ((chld_err.lines > 0) && strstr(chld_err.line[0], "Timeout")) {
			printf (_("%s - External command error: %s\n"), state_text(timeout_state), chld_err.line[0]);
			for (i = 1; i < chld_err.lines; i++) {
				printf ("%s\n", chld_err.line[i]);
			}
			exit (timeout_state);
		} else if (chld_err.lines > 0) {
			printf (_("External command error: %s\n"), chld_err.line[0]);
			for (i = 1; i < chld_err.lines; i++) {
				printf ("%s\n", chld_err.line[i]);
			}
			exit (STATE_UNKNOWN);
		} else {
			printf(_("External command error with no output (return code: %d)\n"), return_code);
			exit (STATE_UNKNOWN);
		}
	}

	if (verbose) {
		for (i = 0; i < chld_out.lines; i++) {
			printf ("%s\n", chld_out.line[i]);
		}
	}

	for (line=0, i=0; line < chld_out.lines; line++, i++) {
		if(calculate_rate)
			conv = "%.10g";
		else
			conv = "%.0f";

		ptr = chld_out.line[line];
		oidname = strpcpy (oidname, ptr, delimiter);
		response = strstr (ptr, delimiter);
		if (response == NULL)
			break;
		response = response + 3;

		if (verbose > 2) {
			printf("Processing oid %i (line %i)\n  oidname: %s\n  response: %s\n", i+1, line+1, oidname, response);
		}

		if (strict_mode && strncmp(oids[i], oidname, strlen(oids[i]))) {
			die( STATE_UNKNOWN, _("UNKNOWN - Expected OID %s did not match actual OID %s.\n"), oids[i], oidname);
		}

		/* Clean up type array - Sol10 does not necessarily zero it out */
		bzero(type, sizeof(type));

		is_counter=0;
		is_ticks = 0;
		/* We strip out the datatype indicator for PHBs */
		if (strstr (response, "Gauge: ")) {
			show = strstr (response, "Gauge: ") + 7;
		}
		else if (strstr (response, "Gauge32: ")) {
			show = strstr (response, "Gauge32: ") + 9;
		}
		else if (strstr (response, "Counter32: ")) {
			show = strstr (response, "Counter32: ") + 11;
			is_counter=1;
			if(!calculate_rate)
				strcpy(type, "c");
		}
		else if (strstr (response, "Counter64: ")) {
			show = strstr (response, "Counter64: ") + 11;
			is_counter=1;
			if(!calculate_rate)
				strcpy(type, "c");
		}
		else if (strstr (response, "INTEGER: ")) {
			show = strstr (response, "INTEGER: ") + 9;
		}
		else if (strstr (response, "OID: ")) {
			show = strstr (response, "OID: ") + 5;
		}
		else if (strstr (response, "STRING: ")) {
			show = strstr (response, "STRING: ") + 8;
			conv = "%.10g";

			/* Get the rest of the string on multi-line strings */
			ptr = show;
			COUNT_SEQ(ptr, bk_count, dq_count)
			while (dq_count && ptr[0] != '\n' && ptr[0] != '\0') {
				ptr++;
				GOBBLE_TOS(ptr, "\n\"\\")
				COUNT_SEQ(ptr, bk_count, dq_count)
			}

			if (dq_count) { /* unfinished line */
				/* copy show verbatim first */
				if (!mult_resp) mult_resp = strdup("");
				xasprintf (&mult_resp, "%s%s:\n%s\n", mult_resp, oids[i], show);
				/* then strip out unmatched double-quote from single-line output */
				if (show[0] == '"') show++;

				/* Keep reading until we match end of double-quoted string */
				for (line++; line < chld_out.lines; line++) {
					ptr = chld_out.line[line];
					xasprintf (&mult_resp, "%s%s\n", mult_resp, ptr);

					COUNT_SEQ(ptr, bk_count, dq_count)
					while (dq_count && ptr[0] != '\n' && ptr[0] != '\0') {
						ptr++;
						GOBBLE_TOS(ptr, "\n\"\\")
						COUNT_SEQ(ptr, bk_count, dq_count)
					}
					/* Break for loop before next line increment when done */
					if (!dq_count) break;
				}
			}

		}
		else if (strstr (response, "Timeticks: ")) {
			show = strstr (response, "Timeticks: ");
			is_ticks = 1;
		}
		else if (strstr (response, "IpAddress: ")) {
			show = strstr (response, "IpAddress: ") + 11;
		}
		else {
			/* This branch is expected to be error-handling only */
			show = response;
			show_length = strlen(show);
			for (j = 0; j < show_length; j++){
				if (isspace(show[j])){
					die (STATE_UNKNOWN,_("Unrecognized OID name returned (%s)\n"), show);
				}
			}
		}
		iresult = STATE_DEPENDENT;

		/* Process this block for numeric comparisons */
		/* Make some special values,like Timeticks numeric only if a threshold is defined */
		if (thlds[i]->warning || thlds[i]->critical || calculate_rate || is_ticks || offset != 0.0 || multiplier != 1.0) {
			/* Find the first instance of the '(' character - the value of the OID should be contained in parens */
			if ((ptr = strpbrk(show, "(")) != NULL) { /* Timetick */
				ptr++;
			} else if ((ptr = strpbrk(show, "-0123456789")) == NULL) { /* Counter, gauge, or integer */
				die (STATE_UNKNOWN,_("No valid data returned (%s)\n"), show);
			}

			while (i >= response_size) {
				response_size += OID_COUNT_STEP;
				response_value = realloc(response_value, response_size * sizeof(*response_value));
			}
			response_value[i] = strtod (ptr, NULL) + offset;
			// This defaults to 1.0 so it's safe to multiply
			response_value[i] *= multiplier;

			if(calculate_rate) {
				if(check_throughput) {
					iresult = STATE_OK;
				}
				else if (previous_state!=NULL) {
					duration = current_time-previous_state->time;
					if(duration<=0)
						die(STATE_UNKNOWN,_("Time duration between plugin calls is invalid"));
					temp_double = response_value[i]-previous_value[i];
					/* Simple overflow catcher (same as in rrdtool, rrd_update.c) */
					if(is_counter) {
						if(temp_double<(double)0.0)
							temp_double+=(double)4294967296.0; /* 2^32 */
						if(temp_double<(double)0.0)
							temp_double+=(double)18446744069414584320.0; /* 2^64-2^32 */;
					}
					/* Convert to per second, then use multiplier */
					temp_double = temp_double/duration*rate_multiplier;
					iresult = get_status(temp_double, thlds[i]);
					xasprintf (&show, conv, temp_double);
				}
			} else {
				iresult = get_status(response_value[i], thlds[i]);
				if(is_ticks) {
					xasprintf (&show, "%s", response);
				}
				else { 
					xasprintf (&show, conv, response_value[i]);
				}
			}
		}

		/* Process this block for string matching */
		else if (eval_size > i && eval_method[i] & CRIT_STRING) {
			if (strcmp (show, string_value))
				iresult = (invert_search==0) ? STATE_CRITICAL : STATE_OK;
			else
				iresult = (invert_search==0) ? STATE_OK : STATE_CRITICAL;
		}

		/* Process this block for regex matching */
		else if (eval_size > i && eval_method[i] & CRIT_REGEX) {
			excode = regexec (&preg, response, 10, pmatch, eflags);
			if (excode == 0) {
				iresult = (invert_search==0) ? STATE_OK : STATE_CRITICAL;
			}
			else if (excode != REG_NOMATCH) {
				regerror (excode, &preg, errbuf, MAX_INPUT_BUFFER);
				printf (_("Execute Error: %s\n"), errbuf);
				exit (STATE_CRITICAL);
			}
			else {
				iresult = (invert_search==0) ? STATE_CRITICAL : STATE_OK;
			}
		}

		/* Process this block for existence-nonexistence checks */
		/* TV: Should this be outside of this else block? */
		else {
			if (eval_size > i && eval_method[i] & CRIT_PRESENT)
				iresult = STATE_CRITICAL;
			else if (eval_size > i && eval_method[i] & WARN_PRESENT)
				iresult = STATE_WARNING;
			else if (response && iresult == STATE_DEPENDENT)
				iresult = STATE_OK;
		}

		/* Result is the worst outcome of all the OIDs tested */
		result = max_state (result, iresult);
		
		/* Prepend a label for this OID if there is one */
		if (nlabels >= (size_t)1 && (size_t)i < nlabels && labels[i] != NULL)
			xasprintf (&outbuff, "%s%s%s %s%s%s", outbuff,
				(i == 0) ? " " : output_delim,
				labels[i], mark (iresult), show, mark (iresult));
		else
			xasprintf (&outbuff, "%s%s%s%s%s", outbuff, (i == 0) ? " " : output_delim,
				mark (iresult), show, mark (iresult));

		/* Append a unit string for this OID if there is one */
		if (nunits > (size_t)0 && (size_t)i < nunits && unitv[i] != NULL)
			xasprintf (&outbuff, "%s %s", outbuff, unitv[i]);
		
		/* Write perfdata with whatever can be parsed by strtod, if possible */
		ptr = NULL;
		if(is_ticks) {
			show = strstr (response, "Timeticks: ");
			show = strpbrk (show, "-0123456789");
		}
		strtod(show, &ptr);
		if (ptr > show) {

			/* use either specified label or oid as label */
			if (perf_labels 
				&& (nlabels >= (size_t)1) 
				&& ((size_t)i < nlabels) 
				&& labels[i] != NULL) {

					temp_string=labels[i];
			}
			else {
				temp_string = oidname;
			}

			/* check the label for space, equal, singlequote or doublequote */
			if (strpbrk(temp_string, " ='\"") == NULL) {

				/* if it doesn't have any - we can just use it as the label */
				strncat(perfstr, temp_string, sizeof(perfstr) - strlen(perfstr) - 1);

			} else {

				/* if it does have one of those characters, we need
				   to find a way to adequately quote it */
				if (strpbrk(temp_string, "'") == NULL) {
					quote_string="'";
				} else {
					quote_string="\"";
				}

				strncat(perfstr, quote_string, sizeof(perfstr) - strlen(perfstr) - 1);
				strncat(perfstr, temp_string, sizeof(perfstr) - strlen(perfstr) - 1);
				strncat(perfstr, quote_string, sizeof(perfstr) - strlen(perfstr) - 1);
			}

			/* append the equal */
			strncat(perfstr, "=", sizeof(perfstr) - strlen(perfstr) - 1);
			len = sizeof(perfstr) - strlen(perfstr) - 1;

			/* and then the data itself from the response */
			strncat(perfstr, show, (len > ptr - show) ? ptr - show : len);

			/* now append the unit of measurement */
			if ((nunits > (size_t)0) 
				&& ((size_t)i < nunits) 
				&& (unitv[i] != NULL)) {

					xasprintf(&temp_string, "%s", unitv[i]);
					strncat(perfstr, temp_string, sizeof(perfstr) - strlen(perfstr) - 1);
			}

			/* and the type, if any */
			if (type) {
				strncat(perfstr, type, sizeof(perfstr) - strlen(perfstr) - 1);
			}

			/* add warn/crit to perfdata */
			if (thlds[i]->warning || thlds[i]->critical) {

				strncat(perfstr, ";", sizeof(perfstr) - strlen(perfstr) - 1);

				/* print the warning string if it exists */
				if (thlds[i]->warning_string) {

					xasprintf(&temp_string, "%s", thlds[i]->warning_string);
					strncat(perfstr, temp_string, sizeof(perfstr) - strlen(perfstr) - 1);
				}
				strncat(perfstr, ";", sizeof(perfstr)-strlen(perfstr)-1);

				/* print the critical string if it exists */
				if (thlds[i]->critical_string) {

					xasprintf(&temp_string, "%s", thlds[i]->critical_string);
					strncat(perfstr, temp_string, sizeof(perfstr) - strlen(perfstr) - 1);
				}
				strncat(perfstr, ";", sizeof(perfstr) - strlen(perfstr) - 1);
			}

			/* remove trailing semi-colons for guideline adherence */
			len = strlen(perfstr) - 1;
			if (perfstr[len] == ';') {
				perfstr[len] = '\0';
			}

			/* we do not add any min/max value */

			strncat(perfstr, " ", sizeof(perfstr) - strlen(perfstr) - 1);
		}

	} /* for (line=0, i=0; line < chld_out.lines; line++, i++) */
	
	total_oids=i;

	/* Save state data, as all data collected now */
    if (check_throughput) {
			OctetData current = {0};
			OctetData previous = {0};
		int state = STATE_UNKNOWN;
		const char *unit_str = (units && *units) ? units : "mbps";
		const char *db_iface = db_key ? db_key : "unknown";

		if (verbose > 1) printf("DEBUG: Database: %s\n", db_path);

		current.timestamp = current_time;
		
		/* Re-parse output for full 64-bit precision */
		int val_idx = 0;
		if (verbose > 1) printf("DEBUG: Parsing %d output lines\n", chld_out.lines);
		for (i = 0; i < chld_out.lines && val_idx < 2; i++) {
			char *ptr = chld_out.line[i];
			if (strstr(ptr, delimiter)) {
				char *val_ptr = strstr(ptr, delimiter) + strlen(delimiter);
				if (strstr(val_ptr, "Counter64:")) val_ptr = strstr(val_ptr, "Counter64:") + 10;
				else if (strstr(val_ptr, "Counter32:")) val_ptr = strstr(val_ptr, "Counter32:") + 10;
				else if (strstr(val_ptr, "Gauge32:")) val_ptr = strstr(val_ptr, "Gauge32:") + 8;
				else if (strstr(val_ptr, "INTEGER:")) val_ptr = strstr(val_ptr, "INTEGER:") + 8;
				
				while (*val_ptr == ' ' || *val_ptr == '\t') val_ptr++;
				
				unsigned long long val = strtoull(val_ptr, NULL, 10);
				if (val_idx == 0) current.in_octets = val;
				else if (val_idx == 1) current.out_octets = val;
				val_idx++;
			}
		}

		/* Determine counter size: 64-bit for ifHC* , otherwise 32-bit */
		current.counter_bits = (oids[0] && strstr(oids[0], "1.3.6.1.2.1.31")) ? 64 : 32;
		
		if (db_read_state(db_path, server_address, db_iface, &previous) != STATE_OK) {
			db_write_state(db_path, server_address, db_iface, &current);
			printf("OK - Baseline established for %s db_key %s\n", server_address, db_key);
			exit(STATE_OK);
		}

		double bw_in = calculate_throughput(
			calculate_wraparound(current.in_octets, previous.in_octets, current.counter_bits),
			current.timestamp - previous.timestamp,
			unit_str
		);
		double bw_out = calculate_throughput(
			calculate_wraparound(current.out_octets, previous.out_octets, current.counter_bits),
			current.timestamp - previous.timestamp,
			unit_str
		);

		double val_in = convert_throughput(bw_in, unit_str, 1);
		double val_out = convert_throughput(bw_out, unit_str, 1);

		if (verbose > 2) {
			printf("DEBUG: total_oids=%d, thlds[0]=%p", total_oids, (void*)thlds[0]);
			if (total_oids > 1) printf(", thlds[1]=%p", (void*)thlds[1]);
			printf("\n");
		}

		int status_in = get_status(val_in, thlds[0]);
		int status_out = (total_oids > 1) ? get_status(val_out, thlds[1]) : STATE_OK;

		state = max_state(status_in, status_out);
		db_write_state(db_path, server_address, db_iface, &current);

		printf("%s - In: %.2f %s, Out: %.2f %s | in=%.2f%s out=%.2f%s\n",
			state_text(state),
			val_in, unit_str, val_out, unit_str,
			val_in, unit_str, val_out, unit_str);

		exit(state);
	}

	if(calculate_rate) {
		string_length=1024;
		state_string=malloc(string_length);
		if(state_string==NULL)
			die(STATE_UNKNOWN, _("Cannot malloc"));

		current_length=0;
		for(i=0; i<total_oids; i++) {
			xasprintf(&temp_string,"%.0f",response_value[i]);
			if(temp_string==NULL)
				die(STATE_UNKNOWN,_("Cannot asprintf()"));
			response_length = strlen(temp_string);
			if(current_length+response_length>string_length) {
				string_length=current_length+1024;
				state_string=realloc(state_string,string_length);
				if(state_string==NULL)
					die(STATE_UNKNOWN, _("Cannot realloc()"));
			}
			strcpy(&state_string[current_length],temp_string);
			current_length=current_length+response_length;
			state_string[current_length]=':';
			current_length++;
			free(temp_string);
		}
		state_string[--current_length]='\0';
		if (verbose > 2)
			printf("State string=%s\n",state_string);

		/* This is not strictly the same as time now, but any subtle variations will cancel out */
		np_state_write_string(current_time, state_string );
		if(previous_state==NULL) {
			/* Or should this be highest state? */
			die( STATE_OK, _("No previous data to calculate rate - assume okay" ) );
		}
	}
	
	printf ("%s %s -%s %s\n", label, state_text (result), outbuff, perfstr);
	if (mult_resp) printf ("%s", mult_resp);

	return result;
}



/* process command-line arguments */
int
process_arguments (int argc, char **argv)
{
	char *ptr;
	int c = 1;
	int j = 0, jj = 0, ii = 0;

	int option = 0;
	static struct option longopts[] = {
		STD_LONG_OPTS,
		{"community", required_argument, 0, 'C'},
		{"oid", required_argument, 0, 'o'},
		{"object", required_argument, 0, 'o'},
		{"delimiter", required_argument, 0, 'd'},
		{"output-delimiter", required_argument, 0, 'D'},
		{"string", required_argument, 0, 's'},
		{"timeout", required_argument, 0, 't'},
		{"regex", required_argument, 0, 'r'},
		{"ereg", required_argument, 0, 'r'},
		{"eregi", required_argument, 0, 'R'},
		{"label", required_argument, 0, 'l'},
		{"units", required_argument, 0, 'u'},
		{"port", required_argument, 0, 'p'},
		{"retries", required_argument, 0, 'e'},
		{"miblist", required_argument, 0, 'm'},
		{"protocol", required_argument, 0, 'P'},
		{"context", required_argument, 0, 'N'},
		{"seclevel", required_argument, 0, 'L'},
		{"secname", required_argument, 0, 'U'},
		{"authproto", required_argument, 0, 'a'},
		{"privproto", required_argument, 0, 'x'},
		{"authpasswd", required_argument, 0, 'A'},
		{"privpasswd", required_argument, 0, 'X'},
		{"next", no_argument, 0, 'n'},
		{"strict", no_argument, 0, STRICT_MODE},
		{"rate", no_argument, 0, L_CALCULATE_RATE},
		{"rate-multiplier", required_argument, 0, L_RATE_MULTIPLIER},
		{"offset", required_argument, 0, L_OFFSET},
		{"multiplier", required_argument, 0, L_MULTIPLIER},
		{"invert-search", no_argument, 0, L_INVERT_SEARCH},
		{"perf-oids", no_argument, 0, 'O'},
		{"ipv4", no_argument, 0, '4'},
		{"ipv6", no_argument, 0, '6'},
		{"status", no_argument, 0, L_STATUS},
		{"throughput", no_argument, 0, L_THROUGHPUT},
		{"counter-bits", required_argument, 0, L_COUNTER_BITS},
		{"interface", required_argument, 0, 'i'},
		{"db-key", required_argument, 0, L_DB_KEY},
		{0, 0, 0, 0}
	};

	if (argc < 2)
		return ERROR;

	/* reverse compatibility for very old non-POSIX usage forms */
	for (c = 1; c < argc; c++) {
		if (strcmp ("-to", argv[c]) == 0)
			strcpy (argv[c], "-t");
		if (strcmp ("-wv", argv[c]) == 0)
			strcpy (argv[c], "-w");
		if (strcmp ("-cv", argv[c]) == 0)
			strcpy (argv[c], "-c");
	}

	while (1) {
		c = getopt_long (argc, argv, "nhvVO46t:c:w:H:C:o:e:E:d:D:s:t:R:r:l:u:p:m:P:N:L:U:a:x:A:X:i:",
									 longopts, &option);

		if (c == -1 || c == EOF)
			break;

		switch (c) {
		case '?':	/* usage */
			usage5 ();
		case 'h':	/* help */
			print_help ();
			exit (STATE_OK);
		case 'V':	/* version */
			print_revision (progname, VERSION);
			exit (STATE_OK);
		case 'v': /* verbose */
			verbose++;
			break;

	/* Connection info */
		case 'C':									/* group or community */
			community = optarg;
			break;
		case 'H':									/* Host or server */
			server_address = optarg;
			break;
		case 'p':	/* TCP port number */
			port = optarg;
			break;
		case 'm':	/* List of MIBS */
			miblist = optarg;
			break;
		case 'n':	/* usesnmpgetnext */
			usesnmpgetnext = TRUE;
			break;
		case 'P':	/* SNMP protocol version */
			proto = optarg;
			break;
		case 'N':	/* SNMPv3 context */
			context = optarg;
			break;
		case 'L':	/* security level */
			seclevel = optarg;
			break;
		case 'U':	/* security username */
			secname = optarg;
			break;
		case 'a':	/* auth protocol */
			authproto = optarg;
			break;
		case 'x':	/* priv protocol */
			privproto = optarg;
			break;
		case 'A':	/* auth passwd */
			authpasswd = optarg;
			break;
		case 'X':	/* priv passwd */
			privpasswd = optarg;
			break;
		case 't':	/* timeout period */
			timeout_interval = parse_timeout_string (optarg);
			break;
	/* Test parameters */
		case 'c':									/* critical threshold */
			critical_thresholds = optarg;
			break;
		case 'w':									/* warning threshold */
			warning_thresholds = optarg;
			break;
		case 'e': /* PRELIMINARY - may change */
		case 'E': /* PRELIMINARY - may change */
			if (!is_integer (optarg))
				usage2 (_("Retries interval must be a positive integer"), optarg);
			else
				retries = atoi(optarg);
			break;
		case 'o':									/* object identifier */
			if ( strspn( optarg, "0123456789.," ) != strlen( optarg ) ) {
					/*
					 * we have something other than digits, periods and comas,
					 * so we have a mib variable, rather than just an SNMP OID,
					 * so we have to actually read the mib files
					 */
					needmibs = TRUE;
			}
			for (ptr = strtok(optarg, ", "); ptr != NULL; ptr = strtok(NULL, ", "), j++) {
				while (j >= oids_size) {
					oids_size += OID_COUNT_STEP;
					oids = realloc(oids, oids_size * sizeof (*oids));
				}
				oids[j] = strdup(ptr);
			}
			numoids = j;
			if (c == 'E' || c == 'e') {
				jj++;
				ii++;
				while (j+1 >= eval_size) {
					eval_size += OID_COUNT_STEP;
					eval_method = realloc(eval_method, eval_size * sizeof(*eval_method));
					memset(eval_method + eval_size - OID_COUNT_STEP, 0, 8);
				}
				if (c == 'E')
					eval_method[j+1] |= WARN_PRESENT;
				else if (c == 'e')
					eval_method[j+1] |= CRIT_PRESENT;
			}
			break;
		case 's':									/* string or substring */
			strncpy (string_value, optarg, sizeof (string_value) - 1);
			string_value[sizeof (string_value) - 1] = 0;
			while (jj >= eval_size) {
				eval_size += OID_COUNT_STEP;
				eval_method = realloc(eval_method, eval_size * sizeof(*eval_method));
				memset(eval_method + eval_size - OID_COUNT_STEP, 0, 8);
			}
			eval_method[jj++] = CRIT_STRING;
			ii++;
			break;
		case 'R':									/* regex */
			cflags = REG_ICASE;
		case 'r':									/* regex */
			cflags |= REG_EXTENDED | REG_NOSUB | REG_NEWLINE;
			strncpy (regex_expect, optarg, sizeof (regex_expect) - 1);
			regex_expect[sizeof (regex_expect) - 1] = 0;
			errcode = regcomp (&preg, regex_expect, cflags);
			if (errcode != 0) {
				regerror (errcode, &preg, errbuf, MAX_INPUT_BUFFER);
				printf (_("Could Not Compile Regular Expression"));
				return ERROR;
			}
			while (jj >= eval_size) {
				eval_size += OID_COUNT_STEP;
				eval_method = realloc(eval_method, eval_size * sizeof(*eval_method));
				memset(eval_method + eval_size - OID_COUNT_STEP, 0, 8);
			}
			eval_method[jj++] = CRIT_REGEX;
			ii++;
			break;

	/* Format */
		case 'd':									/* delimiter */
			delimiter = strscpy (delimiter, optarg);
			break;
		case 'D':									/* output-delimiter */
			output_delim = strscpy (output_delim, optarg);
			break;
		case 'l':									/* label */
			nlabels++;
			if (nlabels > labels_size) {
				labels_size += 8;
				labels = realloc (labels, labels_size * sizeof(*labels));
				if (labels == NULL)
					die (STATE_UNKNOWN, _("Could not reallocate labels[%d]"), (int)nlabels);
			}
			labels[nlabels - 1] = optarg;
			ptr = thisarg (optarg);
			labels[nlabels - 1] = ptr;
			if (ptr[0] == '\'')
				labels[nlabels - 1] = ptr + 1;
			while (ptr && (ptr = nextarg (ptr))) {
				nlabels++;
				if (nlabels > labels_size) {
					labels_size += 8;
					labels = realloc (labels, labels_size * sizeof(*labels));
					if (labels == NULL)
						die (STATE_UNKNOWN, _("Could not reallocate labels\n"));
				}
				ptr = thisarg (ptr);
				if (ptr[0] == '\'')
					labels[nlabels - 1] = ptr + 1;
				else
					labels[nlabels - 1] = ptr;
			}
			break;
		case 'u':									/* units */
			units = optarg;
			nunits++;
			if (nunits > unitv_size) {
				unitv_size += 8;
				unitv = realloc (unitv, unitv_size * sizeof(*unitv));
				if (unitv == NULL)
					die (STATE_UNKNOWN, _("Could not reallocate units [%d]\n"), (int)nunits);
			}
			unitv[nunits - 1] = optarg;
			ptr = thisarg (optarg);
			unitv[nunits - 1] = ptr;
			if (ptr[0] == '\'')
				unitv[nunits - 1] = ptr + 1;
			while (ptr && (ptr = nextarg (ptr))) {
				if (nunits > unitv_size) {
					unitv_size += 8;
					unitv = realloc (unitv, unitv_size * sizeof(*unitv));
					if (units == NULL)
						die (STATE_UNKNOWN, _("Could not realloc() units\n"));
				}
				nunits++;
				ptr = thisarg (ptr);
				if (ptr[0] == '\'')
					unitv[nunits - 1] = ptr + 1;
				else
					unitv[nunits - 1] = ptr;
			}
			break;
		case STRICT_MODE:
			strict_mode = 1;
			break;
		case L_CALCULATE_RATE:
			if(calculate_rate==0)
				np_enable_state(NULL, 1);
			calculate_rate = 1;
			break;
		case L_RATE_MULTIPLIER:
			if(!is_integer(optarg)||((rate_multiplier=atoi(optarg))<=0))
				usage2(_("Rate multiplier must be a positive integer"),optarg);
			break;
		case L_OFFSET:
                        offset=strtod(optarg,NULL);
			break;
		case L_MULTIPLIER:
			multiplier=strtod(optarg,NULL);

			break;
		case L_INVERT_SEARCH:
			invert_search=1;
			break;
		case 'O':
			perf_labels=0;
			break;
		case L_THROUGHPUT:
			check_throughput = 1;
			break;
		case L_STATUS:
			check_status = 1;
			break;
		case L_COUNTER_BITS:
			explicit_counter_bits = atoi(optarg);
			break;
		case L_DB_KEY:
			db_key = optarg;
			break;
		case 'i':
			interface_idx = optarg;
			break;
		case '4':
			break;
		case '6':
			xasprintf(&ip_version, "udp6:");
			if(verbose>2)
				printf("IPv6 detected! Will pass \"udp6:\" to snmpget.\n");
			break;
		}
	}

	if (server_address == NULL)
		server_address = argv[optind];

	if (community == NULL)
		community = strdup (DEFAULT_COMMUNITY);

	/* Automatically append interface index to OIDs if not already present */
	if (interface_idx && numoids > 0 && !check_throughput) {
		int i;
		for (i = 0; i < numoids; i++) {
			if (oids[i]) {
				size_t oid_len = strlen(oids[i]);
				size_t idx_len = strlen(interface_idx);
				
				/* Check if already has .interface_idx suffix */
				if (!(oid_len > idx_len + 1 && oids[i][oid_len - idx_len - 1] == '.' && 
				      strcmp(oids[i] + oid_len - idx_len, interface_idx) == 0)) {
					char *new_oid;
					xasprintf(&new_oid, "%s.%s", oids[i], interface_idx);
					free(oids[i]);
					oids[i] = new_oid;
					if(verbose) printf("Appended interface index to OID: %s\n", new_oid);
				}
			}
		}
	}

	/* Prepare OIDs for Status Mode if interface is specified but no OIDs */
	if (check_status && interface_idx && numoids == 0) {
		char oid1[256];
		snprintf(oid1, sizeof(oid1), "%s", status_oid ? status_oid : "1.3.6.1.2.1.2.2.1.8");
		if (!status_oid) {
			strcat(oid1, ".");
			strcat(oid1, interface_idx);
		}
		
		if (numoids + 1 >= oids_size) {
			oids_size += OID_COUNT_STEP;
			oids = realloc(oids, oids_size * sizeof (*oids));
		}
		oids[numoids++] = strdup(oid1);
	}

	/* Prepare OIDs for Throughput Mode if interface is specified but no OIDs */
	if (check_throughput && interface_idx && numoids == 0) {
		char oid1[256], oid2[256];
		OctetData prev_data = {0};
		int use_64 = (explicit_counter_bits == 64) || 
		             (explicit_counter_bits == 0 && 
		              (db_read_state(db_path, server_address, db_key, &prev_data) != STATE_OK || 
		               prev_data.counter_bits == 64));

		snprintf(oid1, sizeof(oid1), "%s.%s", 
		         use_64 ? "1.3.6.1.2.1.31.1.1.1.6" : "1.3.6.1.2.1.2.2.1.10", interface_idx);
		snprintf(oid2, sizeof(oid2), "%s.%s", 
		         use_64 ? "1.3.6.1.2.1.31.1.1.1.10" : "1.3.6.1.2.1.2.2.1.16", interface_idx);

		if (numoids + 2 >= oids_size) {
			oids_size += OID_COUNT_STEP;
			oids = realloc(oids, oids_size * sizeof (*oids));
		}
		oids[numoids++] = strdup(oid1);
		oids[numoids++] = strdup(oid2);
	}

	return validate_arguments ();
}


/******************************************************************************

@@-
<sect3>
<title>validate_arguments</title>

<para>&PROTO_validate_arguments;</para>

<para>Checks to see if the default miblist needs to be loaded. Also verifies
the authentication and authorization combinations based on protocol version
selected.</para>

<para></para>

</sect3>
-@@
******************************************************************************/



int
validate_arguments ()
{
	/* check whether to load locally installed MIBS (CPU/disk intensive) */
	if (miblist == NULL) {
		if ( strict_mode == TRUE ) {
			miblist = "";
		}
		else if ( needmibs == TRUE ) {
			miblist = strdup (DEFAULT_MIBLIST);
		}
		else {
			miblist = "";			/* don't read any mib files for numeric oids */
		}
	}

	/* Check server_address is given */
	if (server_address == NULL)
		die(STATE_UNKNOWN, _("No host specified\n"));

	/* Check interface index is given when using throughput mode in auto mode */
	if (check_throughput && numoids == 0 && interface_idx == NULL)
		die(STATE_UNKNOWN, _("Interface index (-i) required with --throughput when no -o specified\n"));

	/* Extract interface index from OID if not provided */
	if (check_throughput && numoids > 0 && interface_idx == NULL) {
		const char *last_dot = strrchr(oids[0], '.');
		if (last_dot && last_dot[1] != '\0') {
			interface_idx = strdup(last_dot + 1);
			if(verbose) printf("Extracted interface index from OID: %s\n", interface_idx);
		} else {
			die(STATE_UNKNOWN, _("Could not extract interface index from OID. Specify -i explicitly.\n"));
		}
	}

	/* Validate interface index is numeric, units format, and database keys */
	if ((check_throughput || check_status) && interface_idx != NULL) {
		char *endptr;
		strtol(interface_idx, &endptr, 10);
		if (*endptr != '\0')
			die(STATE_UNKNOWN, _("Interface index (-i) must be numeric (e.g., -i 77)\n"));
		
		if (db_key == NULL) db_key = interface_idx;
		if (validate_db_key(db_key) != 0)
			die(STATE_UNKNOWN, _("Invalid database key '%s'\n"), db_key);
	}

	if (check_throughput && units != NULL) {
		static const char *valid_units[] = {"bps", "kbps", "mbps", "gbps", "Bps", "KBps", "MBps", "GBps", NULL};
		int i, valid = 0;
		for (i = 0; valid_units[i]; i++) {
			if (strcmp(units, valid_units[i]) == 0) {
				valid = 1;
				break;
			}
		}
		if (!valid)
			die(STATE_UNKNOWN, _("Invalid units '%s'. Must be: bps, kbps, mbps, gbps, Bps, KBps, MBps, or GBps\n"), units);
	}

	if (server_address != NULL && validate_db_key(server_address) != 0)
		die(STATE_UNKNOWN, _("Invalid server address '%s'\n"), server_address);

	/* Check oid is given (except for throughput/status auto mode) */
	if (numoids == 0 && !check_throughput && !check_status)
		die(STATE_UNKNOWN, _("No OIDs specified\n"));

	if (proto == NULL)
		xasprintf(&proto, DEFAULT_PROTOCOL);

	if ((strcmp(proto,"1") == 0) || (strcmp(proto, "2c")==0)) {	/* snmpv1 or snmpv2c */
		numauthpriv = 2;
		authpriv = calloc (numauthpriv, sizeof (char *));
		authpriv[0] = strdup ("-c");
		authpriv[1] = strdup (community);
	}
	else if ( strcmp (proto, "3") == 0 ) {		/* snmpv3 args */
		if (!(context == NULL)) {
			numcontext = 2;
			contextargs = calloc (numcontext, sizeof (char *));
			contextargs[0] = strdup ("-n");
			contextargs[1] = strdup (context);
		}
		
		if (seclevel == NULL)
			xasprintf(&seclevel, "noAuthNoPriv");

		if (secname == NULL)
			die(STATE_UNKNOWN, _("Required parameter: %s\n"), "secname");

		if (strcmp(seclevel, "noAuthNoPriv") == 0) {
			numauthpriv = 4;
			authpriv = calloc (numauthpriv, sizeof (char *));
			authpriv[0] = strdup ("-l");
			authpriv[1] = strdup ("noAuthNoPriv");
			authpriv[2] = strdup ("-u");
			authpriv[3] = strdup (secname);
		} else {
			if (! ( (strcmp(seclevel, "authNoPriv")==0) || (strcmp(seclevel, "authPriv")==0) ) ) {
				usage2 (_("Invalid seclevel"), seclevel);
			}

			if (authproto == NULL )
				xasprintf(&authproto, DEFAULT_AUTH_PROTOCOL);

			if (authpasswd == NULL)
				die(STATE_UNKNOWN, _("Required parameter: %s\n"), "authpasswd");

			if ( strcmp(seclevel, "authNoPriv") == 0 ) {
				numauthpriv = 8;
				authpriv = calloc (numauthpriv, sizeof (char *));
				authpriv[0] = strdup ("-l");
				authpriv[1] = strdup ("authNoPriv");
				authpriv[2] = strdup ("-a");
				authpriv[3] = strdup (authproto);
				authpriv[4] = strdup ("-u");
				authpriv[5] = strdup (secname);
				authpriv[6] = strdup ("-A");
				authpriv[7] = strdup (authpasswd);
			} else if ( strcmp(seclevel, "authPriv") == 0 ) {
				if (privproto == NULL )
					xasprintf(&privproto, DEFAULT_PRIV_PROTOCOL);

				if (privpasswd == NULL)
					die(STATE_UNKNOWN, _("Required parameter: %s\n"), "privpasswd");

				numauthpriv = 12;
				authpriv = calloc (numauthpriv, sizeof (char *));
				authpriv[0] = strdup ("-l");
				authpriv[1] = strdup ("authPriv");
				authpriv[2] = strdup ("-a");
				authpriv[3] = strdup (authproto);
				authpriv[4] = strdup ("-u");
				authpriv[5] = strdup (secname);
				authpriv[6] = strdup ("-A");
				authpriv[7] = strdup (authpasswd);
				authpriv[8] = strdup ("-x");
				authpriv[9] = strdup (privproto);
				authpriv[10] = strdup ("-X");
				authpriv[11] = strdup (privpasswd);
			}
		}

	}
	else {
		usage2 (_("Invalid SNMP version"), proto);
	}

	return OK;
}



/* trim leading whitespace
	 if there is a leading quote, make sure it balances */

char *
thisarg (char *str)
{
	str += strspn (str, " \t\r\n");	/* trim any leading whitespace */
	if (str[0] == '\'') {	/* handle SIMPLE quoted strings */
		if (strlen (str) == 1 || !strstr (str + 1, "'"))
			die (STATE_UNKNOWN, _("Unbalanced quotes\n"));
	}
	return str;
}



/* if there's a leading quote, advance to the trailing quote
	 set the trailing quote to '\x0'
	 if the string continues, advance beyond the comma */

char *
nextarg (char *str)
{
	if (str[0] == '\'') {
		str[0] = 0;
		if (strlen (str) > 1) {
			str = strstr (str + 1, "'");
			return (++str);
		}
		else {
			return NULL;
		}
	}
	if (str[0] == ',') {
		str[0] = 0;
		if (strlen (str) > 1) {
			return (++str);
		}
		else {
			return NULL;
		}
	}
	if ((str = strstr (str, ",")) && strlen (str) > 1) {
		str[0] = 0;
		return (++str);
	}
	return NULL;
}



void
print_help (void)
{
	print_revision (progname, VERSION);

	printf (COPYRIGHT, copyright, email);

	printf ("%s\n", _("Check status of remote machines and obtain system information via SNMP"));

	printf ("\n\n");

	print_usage ();

	printf (UT_HELP_VRSN);
	printf (UT_EXTRA_OPTS);
	printf (UT_IPv46);

	printf (UT_HOST_PORT, 'p', DEFAULT_PORT);

	/* SNMP and Authentication Protocol */
	printf (" %s\n", "-n, --next");
	printf ("    %s\n", _("Use SNMP GETNEXT instead of SNMP GET"));
	printf (" %s\n", "-P, --protocol=[1|2c|3]");
	printf ("    %s\n", _("SNMP protocol version"));
	printf (" %s\n", "-N, --context=CONTEXT");
	printf ("    %s\n", _("SNMPv3 context"));
	printf (" %s\n", "-L, --seclevel=[noAuthNoPriv|authNoPriv|authPriv]");
	printf ("    %s\n", _("SNMPv3 securityLevel"));
	printf (" %s\n", "-a, --authproto=[MD5|SHA]");
	printf ("    %s\n", _("SNMPv3 auth proto"));
	printf (" %s\n", "-x, --privproto=[DES|AES]");
	printf ("    %s\n", _("SNMPv3 priv proto (default DES)"));

	/* Authentication Tokens*/
	printf (" %s\n", "-C, --community=STRING");
	printf ("    %s ", _("Optional community string for SNMP communication"));
	printf ("(%s \"%s\")\n", _("default is") ,DEFAULT_COMMUNITY);
	printf (" %s\n", "-U, --secname=USERNAME");
	printf ("    %s\n", _("SNMPv3 username"));
	printf (" %s\n", "-A, --authpasswd=PASSWORD");
	printf ("    %s\n", _("SNMPv3 authentication password"));
	printf (" %s\n", "-X, --privpasswd=PASSWORD");
	printf ("    %s\n", _("SNMPv3 privacy password"));

	/* OID Stuff */
	printf (" %s\n", "-o, --oid=OID(s)");
	printf ("    %s\n", _("Object identifier(s) or SNMP variables whose value you wish to query"));
	printf (" %s\n", "-m, --miblist=STRING");
	printf ("    %s\n", _("List of MIBS to be loaded (default = none if using numeric OIDs or 'ALL'"));
	printf ("    %s\n", _("for symbolic OIDs.)"));
	printf (" %s\n", "-d, --delimiter=STRING");
	printf ("    %s \"%s\"\n", _("Delimiter to use when parsing returned data. Default is"), DEFAULT_DELIMITER);
	printf ("    %s\n", _("Any data on the right hand side of the delimiter is considered"));
	printf ("    %s\n", _("to be the data that should be used in the evaluation."));

	/* Tests Against Integers */
	printf (" %s\n", "-w, --warning=THRESHOLD(s)");
	printf ("    %s\n", _("Warning threshold range(s)"));
	printf (" %s\n", "-c, --critical=THRESHOLD(s)");
	printf ("    %s\n", _("Critical threshold range(s)"));
	printf (" %s\n", "--rate");
	printf ("    %s\n", _("Enable rate calculation. See 'Rate Calculation' below"));
	printf (" %s\n", "--rate-multiplier");
	printf ("    %s\n", _("Converts rate per second. For example, set to 60 to convert to per minute"));
	printf (" %s\n", "--offset=OFFSET");
	printf ("    %s\n", _("Add/subtract the specified OFFSET to numeric sensor data"));
	printf (" %s\n", "--multiplier=MULTIPLIER");
	printf ("    %s\n", _("Multiply the numeric sensor data by MULTIPLIER before doing comparisons"));

	/* Tests Against Strings */
	printf (" %s\n", "-s, --string=STRING");
	printf ("    %s\n", _("Return OK state (for that OID) if STRING is an exact match"));
	printf (" %s\n", "-r, --ereg=REGEX");
	printf ("    %s\n", _("Return OK state (for that OID) if extended regular expression REGEX matches"));
	printf (" %s\n", "-R, --eregi=REGEX");
	printf ("    %s\n", _("Return OK state (for that OID) if case-insensitive extended REGEX matches"));
	printf (" %s\n", "--invert-search");
	printf ("    %s\n", _("Invert search result (CRITICAL if found)"));

	/* Output Formatting */
	printf (" %s\n", "-l, --label=STRING");
	printf ("    %s\n", _("Prefix label for output from plugin"));
	printf (" %s\n", "-u, --units=STRING");
	printf ("    %s\n", _("Units label(s) for output data (e.g., 'sec.')."));
	printf ("    %s\n", _("For --throughput mode: bps, kbps, mbps, gbps (bits/sec) or Bps, KBps, MBps, GBps (bytes/sec)"));
	printf (" %s\n", "-D, --output-delimiter=STRING");
	printf ("    %s\n", _("Separates output on multiple OID requests"));

	printf (UT_CONN_TIMEOUT, DEFAULT_SOCKET_TIMEOUT);
	printf (" %s\n", "-e, --retries=INTEGER");
	printf ("    %s\n", _("Number of retries to be used in the requests"));

	printf (" %s\n", "-O, --perf-oids");
	printf ("    %s\n", _("Label performance data with OIDs instead of --label's"));
	printf (" %s\n", "--strict");
	printf ("    %s\n", _("Enable strict mode: arguments to -o will be checked against the OID"));
	printf ("    %s\n", _("returned by snmpget. If they don't match, the plugin returns UNKNOWN."));

	/* Throughput Monitoring Options */
	printf ("\n");
	printf (" %s\n", _("Throughput Monitoring:"));
	printf (" %s\n", "-i, --interface=STRING");
	printf ("    %s\n", _("Interface index/identifier (REQUIRED for --throughput mode)"));
	printf ("    %s\n", _("Used to identify interface in database storage"));
	printf (" %s\n", "--throughput");
	printf ("    %s\n", _("Enable throughput monitoring mode"));
	printf ("    %s\n", _("Automatically queries interface octet counters and calculates throughput"));
	printf (" %s\n", "--counter-bits=BITS");
	printf ("    %s\n", _("Explicitly specify counter size: 32 or 64 bits"));
	printf (" %s\n", "--db-key=STRING");
	printf ("    %s\n", _("Database key for storing throughput data (defaults to interface index)"));
	printf ("    %s\n", _("Use this to track by port name, description, or alias instead of index"));

	printf (UT_VERBOSE);

	printf ("\n");
	printf ("%s\n", _("This plugin uses the 'snmpget' command included with the NET-SNMP package."));
	printf ("%s\n", _("if you don't have the package installed, you will need to download it from"));
	printf ("%s\n", _("http://net-snmp.sourceforge.net before you can use this plugin."));

	printf ("\n");
	printf ("%s\n", _("Notes:"));
	printf (" %s\n", _("- Multiple OIDs (and labels) may be indicated by a comma or space-delimited  "));
	printf ("   %s\n", _("list (lists with internal spaces must be quoted)."));

	printf(" -%s", UT_THRESHOLDS_NOTES);

	printf (" %s\n", _("- When checking multiple OIDs, separate ranges by commas like '-w 1:10,1:,:20'"));
	printf (" %s\n", _("- Note that only one string and one regex may be checked at present"));
	printf (" %s\n", _("- All evaluation methods other than PR, STR, and SUBSTR expect that the value"));
	printf ("   %s\n", _("returned from the SNMP query is an unsigned integer."));

	printf("\n");
	printf("%s\n", _("Rate Calculation:"));
	printf(" %s\n", _("In many places, SNMP returns counters that are only meaningful when"));
	printf(" %s\n", _("calculating the counter difference since the last check. check_snmp"));
	printf(" %s\n", _("saves the last state information in a file so that the rate per second"));
	printf(" %s\n", _("can be calculated. Use the --rate option to save state information."));
	printf(" %s\n", _("On the first run, there will be no prior state - this will return with OK."));
	printf(" %s\n", _("The state is uniquely determined by the arguments to the plugin, so"));
	printf(" %s\n", _("changing the arguments will create a new state file."));

	printf (UT_SUPPORT);
}



void
print_usage (void)
{
	printf ("%s\n", _("Usage:"));
	printf ("%s -H <ip_address> -o <OID> [-w warn_range] [-c crit_range]\n",progname);
	printf ("[-C community] [-s string] [-r regex] [-R regexi] [-t timeout] [-e retries]\n");
	printf ("[-l label] [-u units] [-p port-number] [-d delimiter] [-D output-delimiter]\n");
	printf ("[-m miblist] [-P snmp version] [-N context] [-L seclevel] [-U secname]\n");
	printf ("[-a authproto] [-A authpasswd] [-x privproto] [-X privpasswd] [-i interface] [--strict]\n");
	printf ("[--throughput]\n");
}

/* -----------------------------------------------------------------------------
 * Throughput Monitoring Helpers - SQLite Database
 * -----------------------------------------------------------------------------
 */

const char *determine_db_path(void) {
	static char db_file[512];
	const char *paths[] = {"/usr/local/nagios/var", "/etc/nagios-mod-gearman", "/var/tmp"};
	const char *db_name = "nagios_snmp_throughput.db";
	int i;
	
	for (i = 0; i < 3; i++) {
		if (access(paths[i], W_OK) == 0) {
			snprintf(db_file, sizeof(db_file), "%s/%s", paths[i], db_name);
			if (verbose > 1) printf("DEBUG: Using database path: %s\n", db_file);
			return db_file;
		}
	}
	return db_file;
}

int validate_db_key(const char *key) {
	size_t i, len;
	
	if (key == NULL || key[0] == '\0') {
		return -1;
	}
	
	len = strlen(key);
	if (len > 255) {
		return -1;
	}
	
	for (i = 0; i < len; i++) {
		unsigned char c = key[i];
		
		/* Block SQL injection characters */
		if (c == '\'' || c == '"' || c == ';' || c == '\0') {
			return -1;
		}
		
		/* Block SQL comment markers */
		if (c == '-' && i + 1 < len && key[i + 1] == '-') {
			return -1;
		}
		
		/* Block control characters */
		if (c < 32 || c == 127) {
			return -1;
		}
	}
	
	return 0;
}

int db_read_state(const char *db_path, const char *host, const char *iface, OctetData *data) {
	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;

	rc = sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READONLY, NULL);
	if (rc != SQLITE_OK) {
		if (verbose) fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		return STATE_UNKNOWN;
	}

	const char *sql_select = "SELECT timestamp, in_octets, out_octets, counter_bits "
		"FROM states WHERE host = ? AND interface = ?";

	rc = sqlite3_prepare_v2(db, sql_select, -1, &stmt, 0);
	if (rc != SQLITE_OK) {
		if (verbose) fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		return STATE_UNKNOWN;
	}

	sqlite3_bind_text(stmt, 1, host, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, iface, -1, SQLITE_STATIC);

	rc = sqlite3_step(stmt);
	if (rc == SQLITE_ROW) {
		data->timestamp = sqlite3_column_int64(stmt, 0);
		data->in_octets = sqlite3_column_int64(stmt, 1);
		data->out_octets = sqlite3_column_int64(stmt, 2);
		data->counter_bits = sqlite3_column_int(stmt, 3);
		sqlite3_finalize(stmt);
		sqlite3_close(db);
		return STATE_OK;
	}

	sqlite3_finalize(stmt);
	sqlite3_close(db);
	return STATE_UNKNOWN;
}

int db_write_state(const char *db_path, const char *host, const char *iface, const OctetData *data) {
	sqlite3 *db;
	sqlite3_stmt *stmt;
	int rc;

	rc = sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READWRITE, NULL);
	if (rc != SQLITE_OK) {
		if (verbose) fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		return STATE_UNKNOWN;
	}

	const char *sql_upsert = "INSERT OR REPLACE INTO states "
		"(host, interface, timestamp, in_octets, out_octets, counter_bits) "
		"VALUES (?, ?, ?, ?, ?, ?)";

	rc = sqlite3_prepare_v2(db, sql_upsert, -1, &stmt, 0);
	if (rc != SQLITE_OK) {
		if (verbose) fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		return STATE_UNKNOWN;
	}

	sqlite3_bind_text(stmt, 1, host, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, iface, -1, SQLITE_STATIC);
	sqlite3_bind_int64(stmt, 3, data->timestamp);
	sqlite3_bind_int64(stmt, 4, data->in_octets);
	sqlite3_bind_int64(stmt, 5, data->out_octets);
	sqlite3_bind_int(stmt, 6, data->counter_bits);

	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		if (verbose) fprintf(stderr, "Failed to execute statement: %s\n", sqlite3_errmsg(db));
		sqlite3_finalize(stmt);
		sqlite3_close(db);
		return STATE_UNKNOWN;
	}

	sqlite3_finalize(stmt);
	sqlite3_close(db);
	return STATE_OK;
}

unsigned long long calculate_wraparound(unsigned long long current, unsigned long long previous, int counter_bits) {
    if (current >= previous) return current - previous;
    /* 64-bit wrap (rare) = reboot/reset, return 0. 32-bit wrap = add max value */
    return (counter_bits == 64) ? 0 : ((0xFFFFFFFFUL - previous) + current + 1);
}

/* Calculate throughput in bits/sec or bytes/sec depending on unit */
double calculate_throughput(unsigned long long octet_diff, time_t time_diff, const char *unit) {
    if (time_diff <= 0) return 0.0;
    int is_bytes = (unit && (strstr(unit, "Bp") != NULL));
    double multiplier = is_bytes ? 1.0 : 8.0;
    return ((double)octet_diff * multiplier) / (double)time_diff;
}

/* Convert throughput based on unit argument */
double convert_throughput(double value, const char *unit, int to_unit) {
    double divisor = 1.0;
    if (unit) {
        if (strcmp(unit, "kbps") == 0) divisor = 1000.0;
        else if (strcmp(unit, "mbps") == 0) divisor = 1000000.0;
        else if (strcmp(unit, "gbps") == 0) divisor = 1000000000.0;
        else if (strcmp(unit, "KBps") == 0) divisor = 1000.0;
        else if (strcmp(unit, "MBps") == 0) divisor = 1000000.0;
        else if (strcmp(unit, "GBps") == 0) divisor = 1000000000.0;
    }
    return to_unit ? (value / divisor) : (value * divisor);
}
