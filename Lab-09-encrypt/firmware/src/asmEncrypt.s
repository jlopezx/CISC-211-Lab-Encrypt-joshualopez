/*** asmEncrypt.s   ***/

#include <xc.h>

// Declare the following to be in data memory 
.data  

/* create a string */
.global nameStr
.type nameStr,%gnu_unique_object
    
/*** STUDENTS: Change the next line to your name!  **/
nameStr: .asciz "Joshua Lopez"  
.align
 
/* initialize a global variable that C can access to print the nameStr */
.global nameStrPtr
.type nameStrPtr,%gnu_unique_object
nameStrPtr: .word nameStr   /* Assign the mem loc of nameStr to nameStrPtr */

// Define the globals so that the C code can access them
// (in this lab we return the pointer, so strictly speaking,
// does not really need to be defined as global)
// .global cipherText
.type cipherText,%gnu_unique_object

.align
 
@ NOTE: THIS .equ MUST MATCH THE #DEFINE IN main.c !!!!!
@ TODO: create a .h file that handles both C and assembly syntax for this definition
.equ CIPHER_TEXT_LEN, 200
 
// space allocated for cipherText: 200 bytes, prefilled with 0x2A
cipherText: .space CIPHER_TEXT_LEN,0x2A  

.align
 
.global cipherTextPtr
.type cipherTextPtr,%gnu_unique_object
cipherTextPtr: .word cipherText

// Tell the assembler that what follows is in instruction memory    
.text
.align

// Tell the assembler to allow both 16b and 32b extended Thumb instructions
.syntax unified

    
/********************************************************************
function name: asmEncrypt
function description:
     pointerToCipherText = asmEncrypt ( ptrToInputText , key )
     
where:
     input:
     ptrToInputText: location of first character in null-terminated
                     input string. Per calling convention, passed in via r0.
     key:            shift value (K). Range 0-25. Passed in via r1.
     
     output:
     pointerToCipherText: mem location (address) of first character of
                          encrypted text. Returned in r0
     
     function description: asmEncrypt reads each character of an input
                           string, uses a shifted alphabet to encrypt it,
                           and stores the new character value in memory
                           location beginning at "cipherText". After copying
                           a character to cipherText, a pointer is incremented 
                           so that the next letter is stored in the bext byte.
                           Only encrypt characters in the range [a-zA-Z].
                           Any other characters should just be copied as-is
                           without modifications
                           Stop processing the input string when a NULL (0)
                           byte is reached. Make sure to add the NULL at the
                           end of the cipherText string.
     
     notes:
        The return value will always be the mem location defined by
        the label "cipherText".
     
     
********************************************************************/    
.global asmEncrypt
.type asmEncrypt,%function
asmEncrypt:   

    //save the caller's registers, as required by the ARM calling convention
    push {r4-r11,LR}
    
    /* YOUR asmEncrypt CODE BELOW THIS LINE! VVVVVVVVVVVVVVVVVVVVV  */
    ldr r3, =cipherText		/*Holds the memory location of where I need to store the bytes from input text in r0*/
    mov r4, r0			/*r4 will hold a copy of the mem address of input text*/
    mov r5, r1			/*r5 will hold a copy of the key*/
    mov r7, 0			/*Index for cipherText and input text. Used to offset the memory locations by every 
				  iteration in encryption_loop.*/
    
/*This entire encryption_loop is used to check every character in a string starting at memory location in r0
  and if it's a letter, it will shift it by the key(k) stored in r5*/
encryption_loop:
    ldrb r8, [r4, r7]		/*Load byte from input text memory location originally passed through r0, and it offsets
				  its memory address by r7 which is an offset determined by how many times we've looped*/
    cmp r8, 0			/*Check for null terminator since null terminator = 0 in ASCII*/
    beq done			/*If we have a null terminator, then we're done and will branch to done*/

    cmp r8, 'a'			/*Compares current byte to 'a' which is 97*/
    blt check_upper		/*If it's less than 95, then it's a possible uppercase value*/
    cmp r8, 'z'			/*Compares current byte to 'z' which is 122*/
    bgt check_upper		/*If the byte value is greater than 122, then we're not dealing with a lowercase alphabet value*/
    mov r11, 97			/*If we're here, then we have a lowercase value so we move 97 to r11 to convert its ASCII value
				  to its normal alphabet position*/
    b encryption_shift		/*Move to encryption_shift label to handle letter encryption*/

    check_upper:
	cmp r8, 'A'		/*Compares current byte to 'A' which is 65 in ASCII*/
	blt non_alphabet	/*If the byte in r8 is below 65, then we're dealing with a non-alphabet character*/
	cmp r8, 'Z'		/*Compares current byte to 'Z' which is 90 is ASCII*/
	bgt non_alphabet	/*If the byte in r8 is above 90 after this point, then we're dealing with a 
				  non-alphabet character*/
	mov r11, 65		/*If it's within range of 'A'-'Z', then we move 65 to r11 to convert from ASCII to 
				  its letter value position*/	
	b encryption_shift	/*Move to encryption_shift label to handle letter encryption*/


    /*encryption_shift is the heart of the Caesar Cipher where it performs the shift operation to encrypt the letter
      character if applicable*/
    encryption_shift:
	sub r8, r8, r11		/*Subtract the ASCII value to shift the char's decimal value to be aligned with the 
				  alphabet's letter value minus 1. Ex. a = 1-1(0), b = 2-1(1), c = 3-1(2), etc.*/
	add r8, r8, r5		/*Shifting the letter value by the key stored in r5*/

    /*Mod loop is used to keep the byte value within a 26 range (took part of this code from my lab 5)*/
    mod_loop:			/*Loop label to repeat the subtraction and incrementation*/
	cmp r8, 26		/*Used to check if the dividend is less than the divisor, if not, loop*/
	blt shift_handle	/*Checks to see if the dividend(r8) is less than the divisor(26), 
				  if it is, it will branch to the shift_handle label where we shift back to ASCII*/
	sub r8, r8, 26		/*This will subtract the dividend with the divisor to handle the first or next 
				 division iteration*/

	b mod_loop		/*Loops back to repeat the dividend-divisor comparison until dividend is less than 
				  the divisor*/
    shift_handle:
	add r8, r8, r11		/*Add back the ASCII value with either 65(uppercase) or 97(lowercase)*/

    non_alphabet:		/*non_alphabet label is used for non-alphabet character to branch here and just store*/
	strb r8, [r3, r7]	/*Store encrypted byte to cipherText with offset to its memory address*/
	add r7, r7, 1		/*Increment cipherText and input text index, this is the offset and how many times we 
				  looped. We add 1 to offset by 1 byte.*/
	b encryption_loop	/*Go back to check the next byte*/

done:
    mov r0, r3			/*Return the address of cipherText to r0*/
    strb r8, [r3, r7]		/*Store null terminator at the end of cipherText*/
    
    
    /* YOUR asmEncrypt CODE ABOVE THIS LINE! ^^^^^^^^^^^^^^^^^^^^^  */

    // restore the caller's registers, as required by the ARM calling convention
    pop {r4-r11,LR}

    mov pc, lr	 /* asmEncrypt return to caller */
   

/**********************************************************************/   
.end  /* The assembler will not process anything after this directive!!! */
           




