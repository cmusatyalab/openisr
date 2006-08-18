/*
                               Fauxide

		      A virtual disk drive tool
 
               Copyright (c) 2002-2004, Intel Corporation
                          All Rights Reserved

This software is distributed under the terms of the Eclipse Public License, 
Version 1.0 which can be found in the file named LICENSE.  ANY USE, 
REPRODUCTION OR DISTRIBUTION OF THIS SOFTWARE CONSTITUTES RECIPIENT'S 
ACCEPTANCE OF THIS AGREEMENT

*/

/* This program reads a logstats file and produces a list of time samples */
/* Definitions:
 *   num_reads: number of sectors read
 *   num_writes: number of sectors written
 *   num_unique_clean: number of unique sector addresses read but never written
 *   num_unique_dirty: number of unique sector addresses which have been written
 */

/* WARNING: MOST OF THE COUNTS BELOW ARE KEPT IN UNITS OF BLOCKS WHERE
 *   1 BLOCK = 8 SECTORS.  THE PRINT STATEMENTS MAKE THE APPROPRIATE 
 *   ADJUSTMENTS.  
 */

#include <iostream>
#include <fstream>
#include <map>
#include "vulpes_logstats.h"

using namespace std;

/* The number of processor ticks per sec on the source machine */
const unsigned long long tickspersec = 2000000000; /* 2.0 GHz */
/* The sample period in ticks */
const unsigned long long quantum = tickspersec; /* 1 sec quanta */


const unsigned num_sec_per_rec = 8;


/* Structure used to keep track of the number of reads and writes to
 * a particular block address */
struct block_data {
  unsigned reads;
  unsigned writes;

  block_data(void) : reads(0), writes(0) {}
  ~block_data(void) {}
};

/* Mapping of sector addresses to block_data structs */
typedef map<unsigned long, block_data> sector_map_t;

/* Get a logstats hdr from an istream */
istream& 
get_logstats_hdr(istream& in, vulpes_logstats_file_hdr_t *hdr)
{
  return in.read(hdr, sizeof(vulpes_logstats_file_hdr_t));
}

/* Get a logstats record from an istream */
istream& 
get_logstats_ver1_record(istream& in, vulpes_logstats_ver1_record_t *rec)
{
  return in.read(rec, sizeof(vulpes_logstats_ver1_record_t));
}

/* Print a time sample from the sector_map consisting of the number of
 * unique_clean sectors, unique_dirty sectors, sector reads, and sector writes.
 * WARNING: this call traverses the entire map -- it's quite expensive */
void print_time_sample(unsigned sample, const sector_map_t& sector)
{
  sector_map_t::const_iterator iter;
  unsigned r_num_unique_dirty = 0;
  unsigned r_num_unique_clean = 0;
  unsigned r_num_reads = 0;
  unsigned r_num_writes = 0;

  for(iter=sector.begin(); iter!=sector.end(); iter++) {
    if((*iter).second.reads != 0) {
      if((*iter).second.writes == 0) {
	r_num_unique_clean ++;
      }
      r_num_reads += (*iter).second.reads;
    }
    if((*iter).second.writes != 0) {
      r_num_unique_dirty ++;
      r_num_writes += (*iter).second.writes;
    }
  }

  cout<<sample<<" : "<<num_sec_per_rec*r_num_unique_clean<<' '<<num_sec_per_rec*r_num_unique_dirty
      <<' '<<num_sec_per_rec*r_num_reads<<' '<<num_sec_per_rec*r_num_writes<<'\n';
}

/* Print program usage */
void usage(const char *progname)
{
  cout<<"usage: "<<progname<<" <logstats_filename>"<<endl;
}

int main(int argc, char* argv[])
{
  sector_map_t sect;
  vulpes_logstats_file_hdr_t hdr;
  char *filename;
  unsigned long long starttime = 0;
  unsigned long long sample = 1;

  /* Parse the command line */
  if(argc != 2) {
    usage(argv[0]);
    exit(0);
  }
  filename = argv[1];

  /* Open the logstats input file */
  ifstream in(filename);
  if(!in) {
    cout<<"ERROR: unable to open <"<<argv[1]<<">."<<endl;
    exit(1);
  }

  /* Read the header */
  get_logstats_hdr(in, &hdr);
  cout<<"Logstats version: "<<hdr.version<<endl;
  cout<<"Num records: "<<hdr.num_records<<endl;

  /* Read the logstats records and print out sample information */
  cout<<"sample : unique_clean unique_dirty reads writes"<<endl;
  unsigned num_unique_dirty = 0;
  unsigned num_unique_clean = 0;
  unsigned num_reads = 0;
  unsigned num_writes = 0;
  for(unsigned i=0; i<hdr.num_records; i++) {
    unsigned long long rectime;
    vulpes_logstats_ver1_record_t rec;
    bool is_write;

    /* Read the next record */
    get_logstats_ver1_record(in, &rec);

    /* Initial implementations of fauxide always read two sectors at a time */
    if(rec.num_sector != num_sec_per_rec) {
      cout<<"ERROR: unexpected num sectors!"<<endl;
      break;
    }

    /* Derive the timestamp by masking off the R/W byte */
    rectime = (rec.timestamp & 0x00ffffffffffffffull);
    if(starttime == 0) {
      starttime = rectime;
    }

    /* Print out time samples until we reach the quantum which contains rec */
    while((rectime-starttime) > (sample*quantum)) {
      cout<<sample<<" : "<<num_sec_per_rec*num_unique_clean<<' '<<num_sec_per_rec*num_unique_dirty
	  <<' '<<num_sec_per_rec*num_reads<<' '<<num_sec_per_rec*num_writes<<'\n';
      sample ++;
    }

    /* Parse the record and increment the appropriate fields */
    is_write = ((rec.timestamp & 0xff00000000000000ull) ? true : false);
    unsigned addr = rec.start_sector;
    if(is_write) {
      if(sect[addr].writes == 0) {
	num_unique_dirty ++;
	if(sect[addr].reads != 0) {
	  num_unique_clean --;
	}
      }
      sect[addr].writes ++;
      num_writes ++;
    } else {
      if((sect[addr].reads == 0) && 
	 (sect[addr].writes == 0)) {
	num_unique_clean ++;
      }
      sect[addr].reads ++;
      num_reads ++;
    }
  }

  /* Print the final time sample */
  print_time_sample(sample, sect);

  in.close();
}
