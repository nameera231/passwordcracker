#define _GNU_SOURCE
#include <openssl/md5.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <pthread.h>
#include <math.h>


/**
 * This struct is the root of the data structure that will hold users and hashed passwords.
 * This could be any type of data structure you choose: list, array, tree, hash table, etc.
 * Implement this data structure for part B of the lab.
 */

//linked list to hold all the passwords and associated data
typedef struct password_set {

  struct password_set_element* head;

} password_set_t;

//elements in password set
typedef struct password_set_element {

  char* user;
  uint8_t hash[MD5_DIGEST_LENGTH];
 struct  password_set_element* next;
  
} password_set_element_t;



//struct to hold inputs to threads
struct inputs{
  password_set_t* passwords;
  int start;
  int end;
}typedef input_t;

#define MAX_USERNAME_LENGTH 64
#define PASSWORD_LENGTH 6

//keep track of how many passwods have been cracked 
int crack = 0;

//use this to lock crack so it isn't concurrently incremented
pthread_mutex_t lock;

//function to destroy the password set to prevent memory leak
void destroy(password_set_t* s) {
      //check if empty set already
    if(s->head == NULL)
        {
          return;
        }
    else{
      //otherwise delete items
      while(s->head!=NULL)
      { 
        password_set_element_t* pointer = s->head;

        //we need to make sure to free the space used to store the username so this variable is necessary
        char* pointer1 = s->head->user;

        pointer = s->head;
        s->head =pointer->next;
        free(pointer1);
        free(pointer);
      }
}}


/**
 * Initialize a password set.
 * Complete this implementation for part B of the lab.
 *
 * \param passwords  A pointer to allocated memory that will hold a password set
 */


void init_password_set(password_set_t* passwords) {
  // TODO: Initialize any fields you add to your password set structure

  passwords->head = NULL;
    
}
/************************* Part A *************************/
/*********************************************/

/**
 * Find a six character lower-case alphabetic password that hashes
 * to the given hash value. Complete this function for part A of the lab.
 *
 * \param input_hash  An array of MD5_DIGEST_LENGTH bytes that holds the hash of a password
 * \param output      A pointer to memory with space for a six character password + '\0'
 * \returns           0 if the password was cracked. -1 otherwise.
 */
int crack_single_password(uint8_t* input_hash, char* output) {
  // Take our candidate password and hash it using MD5
  char candidate_password[7];
  candidate_password[6] = '\0';
  int i;
  for (i = 0; i < 26; i++)
  {
    candidate_password[0] = i + 'a';
    
    for ( int j = 0; j < 26; j++)
    {
      candidate_password[1] = j + 'a';
      
      for (int k = 0; k < 26; k++)
      {
         candidate_password[2] = k + 'a';
        
        for (int l = 0; l < 26; l++)
        {
          candidate_password[3] = l + 'a';
          
          for (int m = 0; m < 26; m++)
          {
            candidate_password[4] = m + 'a';
            
            for ( int n  = 0; n < 26; n++)
            {
              candidate_password[5] = n + 'a';
              
                  //< This variable holds the password we are trying
                  uint8_t candidate_hash[MD5_DIGEST_LENGTH]; //< This will hold the hash of the candidate password
                  MD5((unsigned char*)candidate_password, strlen(candidate_password), candidate_hash); //< Do the hash
  
                  // Now check if the hash of the candidate password matches the input hash
                  if(memcmp(input_hash, candidate_hash, MD5_DIGEST_LENGTH) == 0) {
                  // Match! Copy the password to the output and return 0 (success)
                    //just print the password here for the same function in part B
                    strncpy(output, candidate_password, PASSWORD_LENGTH+1);
                    return 0;
                  } 
            }
          }
        }
      }
    }}
  return -1;
}



void* crack_passwords_threadfn(void* arg) {
    
    //use the input struct to retrieve arguments
    input_t* input = (input_t*)arg;


    //retrieve the password set 
    password_set_t* passwords = input->passwords;

    
    
    //this is will be used to indicate the starting letter for each thread
    int start = (int)input->start;
    
    //this will be used to indicate the ending letter for each thread
    int end = input->end;

    
      
      char candidate_password[7];//< This variable holds the password we are trying to check -- it is our guess
      
      //end the string properly
      candidate_password[6] = '\0';
      
      for (int i = start; i < end; i++)
      {
        candidate_password[0] = i + 'a';
        
        for ( int j = 0; j < 26; j++)
        {
          candidate_password[1] = j + 'a';
          
          for (int k = 0; k < 26; k++)
          {
            candidate_password[2] = k + 'a';
            
            for (int l = 0; l < 26; l++)
            {
              candidate_password[3] = l + 'a';
              
              for (int m = 0; m < 26; m++)
              {
                candidate_password[4] = m + 'a';
                
                for ( int n  = 0; n < 26; n++)
                { 
                  candidate_password[5] = n + 'a';

                  //this cursor will keep track of our place in the password set
                  password_set_element_t* cursor = passwords->head;

                  uint8_t candidate_hash[MD5_DIGEST_LENGTH]; //< This will hold the hash of the candidate password
                  MD5((unsigned char*)candidate_password, strlen(candidate_password), candidate_hash); //< Do the hash
                     
                  //while begin -- start traversing the password set and checking if our candidate cracks any
                  while(cursor!=NULL)
                   {
                      // Now check if the hash of the candidate password matches the input hash(cursor->hash)
                      if(memcmp(cursor->hash, candidate_hash, MD5_DIGEST_LENGTH) == 0) {
                      
                        //just print the password here since it has been cracked
                        printf("%s %s\n", cursor->user, candidate_password);
                       
                        //crack should be locked when we are updating it to prevent concurrency bugs
                        pthread_mutex_lock(&lock);
                        crack++;
                        pthread_mutex_unlock(&lock);
                        }    
                      
                      cursor=cursor->next;
                  } //while end
                  
                }
              }
            }
          }
        }
      }
      return NULL;
}

/********************* Parts B & C ************************/



/**
 * Add a password to a password set
 * Complete this implementation for part B of the lab.
 *
 * \param passwords   A pointer to a password set initialized with the function above.
 * \param username    The name of the user being added. The memory that holds this string's
 *                    characters will be reused, so if you keep a copy you must duplicate the
 *                    string. I recommend calling strdup().
 * \param password_hash   An array of MD5_DIGEST_LENGTH bytes that holds the hash of this user's
 *                        password. The memory that holds this array will be reused, so you must
 *                        make a copy of this value if you retain it in your data structure.
 */
void add_password(password_set_t* passwords, char* username, uint8_t* password_hash) {
  // TODO: Add the provided user and password hash to your set of passwords

  //set up a new entry in the password set by allocating space
  password_set_element_t* new_entry = (password_set_element_t*)malloc(sizeof(password_set_element_t));

  //set up space for the username associated with password
  new_entry->user = (char*)malloc((strlen(username) * sizeof(char)) + 1);
  
  //we are adding new entry to the start of the password set
  password_set_element_t* temp = passwords->head;
  new_entry->next = temp;
  strcpy(new_entry->user, username);
  memcpy( new_entry->hash,password_hash, MD5_DIGEST_LENGTH);
  passwords->head = new_entry;
}

//write function to free user malloc and also the nodes like in unique list


/**
 * Crack all of the passwords in a set of passwords. The function should print the username
 * and cracked password for each user listed in passwords, separated by a space character.
 * Complete this implementation for part B of the lab.
 *
 * \returns The number of passwords cracked in the list
 */
int crack_password_list(password_set_t* passwords) {

  //initialize lock for our crack variable
  pthread_mutex_init(&lock,NULL);

  //initialize an array to contain all the threads
  pthread_t thread_ids[4];

  //initialize an array for the arguments that go into each thread
  input_t thread_args[4];

  //these will divide the starting and ending letters for the candidate passwords that each thread checks
  
   //int end = start + 6;

  //initilaize inputs and call all the threads
  for (int i = 0; i < 4; i++) {
    
    //pass in the current list of passwords to be cracked
    thread_args[i].passwords = passwords;

    //each thread will get around 6 (last one will have more) letters as their starting letter for the candidate password
    thread_args[i].start =  6*i;

    if(i < 3)
    {    thread_args[i].end = 6*(i+1);}
    else
    {
      //the last thread will have to cater to more letters because 26 does not divide evenly into 4 so the last one has a remainder
      thread_args[i].end = 26;
    }
    //call the thread
    int rc = pthread_create(&thread_ids[i], NULL,  crack_passwords_threadfn, &thread_args[i]);
    if (rc) {
      perror("pthread_create failed");
      exit(2);
    }
  }

  // Join the threads
  for (int i=0; i<4; i++) {
    int rc = pthread_join(thread_ids[i], NULL);
    if (rc) {
      perror("pthread_create failed");
      exit(2);
    }
  }
  
  //stop memory from leaking by freeing the space used by password set
  destroy(passwords);

  //return the number of cracked passwords
  return crack;
}

/******************** Provided Code ***********************/

/**
 * Convert a string representation of an MD5 hash to a sequence
 * of bytes. The input md5_string must be 32 characters long, and
 * the output buffer bytes must have room for MD5_DIGEST_LENGTH
 * bytes.
 *
 * \param md5_string  The md5 string representation
 * \param bytes       The destination buffer for the converted md5 hash
 * \returns           0 on success, -1 otherwise
 */
int md5_string_to_bytes(const char* md5_string, uint8_t* bytes) {
  // Check for a valid MD5 string
  if(strlen(md5_string) != 2 * MD5_DIGEST_LENGTH) return -1;
  
  // Start our "cursor" at the start of the string
  const char* pos = md5_string;
  
  // Loop until we've read enough bytes
  for(size_t i=0; i<MD5_DIGEST_LENGTH; i++) {
    // Read one byte (two characters)
    int rc = sscanf(pos, "%2hhx", &bytes[i]);
    if(rc != 1) return -1;
    
    // Move the "cursor" to the next hexadecimal byte
    pos += 2;
  }
  
  return 0;
}

void print_usage(const char* exec_name) {
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "  %s single <MD5 hash>\n", exec_name);
  fprintf(stderr, "  %s list <password file name>\n", exec_name);
}

int main(int argc, char** argv) {
  if(argc != 3) {
    print_usage(argv[0]);
    exit(1);
  }
  
  if(strcmp(argv[1], "single") == 0) {
    // The input MD5 hash is a string in hexadecimal. Convert it to bytes.
    uint8_t input_hash[MD5_DIGEST_LENGTH];
    if(md5_string_to_bytes(argv[2], input_hash)) {
      fprintf(stderr, "Input has value %s is not a valid MD5 hash.\n", argv[2]);
      exit(1);
    }
    
    // Now call the crack_single_password function
    char result[7];
    if(crack_single_password(input_hash, result)) {
      printf("No matching password found.\n");
    } else {
      printf("%s\n", result);
    }
    
  } else if(strcmp(argv[1], "list") == 0) {
    // Make and initialize a password set
    password_set_t passwords;
    init_password_set(&passwords);
    
    // Open the password file
    FILE* password_file = fopen(argv[2], "r");
    if(password_file == NULL) {
      perror("opening password file");
      exit(2);
    }
  
    int password_count = 0;
  
    // Read until we hit the end of the file
    while(!feof(password_file)) {
      // Make space to hold the username
      char username[MAX_USERNAME_LENGTH];
      
      // Make space to hold the MD5 string
      char md5_string[MD5_DIGEST_LENGTH * 2 + 1];
      
      // Make space to hold the MD5 bytes
      uint8_t password_hash[MD5_DIGEST_LENGTH];

      // Try to read. The space in the format string is required to eat the newline
      if(fscanf(password_file, "%s %s ", username, md5_string) != 2) {
        fprintf(stderr, "Error reading password file: malformed line\n");
        exit(2);
      }

      // Convert the MD5 string to MD5 bytes in our new node
      if(md5_string_to_bytes(md5_string, password_hash) != 0) {
        fprintf(stderr, "Error reading MD5\n");
        exit(2);
      }
      
      // Add the password to the password set
      add_password(&passwords, username, password_hash);
      password_count++;
    }
    
    // Now run the password list cracker
    int cracked = crack_password_list(&passwords);
    
    printf("Cracked %d of %d passwords.\n", cracked, password_count);
    
  } else {
    print_usage(argv[0]);
    exit(1);
  }

  return 0;
}
