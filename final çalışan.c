#include<stdio.h>
#include<conio.h>
#include <string.h>

#include <math.h>
#include <time.h>

//opendir
#include <sys/stat.h>
#include <dirent.h>
#include <windows.h>


#define Nb 4    // rows in matrix, CONSTANT!
#define Nk 8    // columns in key matrix, 4/6/8 for 128/192/256 bit AES
#define Nr 14   // rounds count, 10/12/14 for 128/192/256 bit AES

unsigned char in_state[Nb*Nb]={};
unsigned char in_cipher[Nb*Nb]={0x8E, 0xA2, 0xB7, 0xCA, 0x51, 0x67, 0x45, 0xBF, 0xEA, 0xFC, 0x49, 0x90, 0x4B, 0x49, 0x60, 0x89};
unsigned char in_key[Nb*Nk+1]={};




unsigned char test[Nb*Nb]={0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

unsigned char key[Nb][Nk];
unsigned char state[Nb][Nb];
unsigned char out_16[Nb*Nb];
unsigned char out_32[Nb*Nk];
unsigned char round_keys[Nr+2][Nb*Nb];
unsigned char state_read_bytes_counter=0;


/*
void show_state(void){}

void show_key(void){}
void show_out(unsigned char out[], unsigned char n){}

*/

void show_state(void){
    unsigned char i, j;
    printf("\n\rState:\n\r");
    for(i=0; i<Nb; i++)
    {
        for(j=0; j<Nb; j++)
        {
            printf("%0*x", 2, state[i][j]);
            printf(" ");
        }
        printf("\n\r");
    }
}
void show_key(void){
    unsigned char i, j;
    printf("\n\rKey:\n\r");
    for(i=0; i<Nb; i++)
    {
        for(j=0; j<Nk; j++)
        {
            printf("%0*x", 2, key[i][j]);
            printf(" ");
        }
        printf("\n\r");
    }
}
void show_out(unsigned char out[], unsigned char n){
    unsigned char i;
    for(i=0; i<(Nb*n); i++)
        printf("%0*x", 2, out[i]);
    printf("\n\r");
}
void clear_screen(void){}

void DEMO_ENCRYPT(void);
void DEMO_DECRYPT(void);
void DEMO_ROUND_KEY(void);
void DEMO_RANDOM_KEY(void);
void DEMO_STATE_STREAM_RW(void);
void DEMO_RND_16_TEST(void);
void DEMO_RND_256_TEST(void);
void DEMO_RND_256_PART_TEST(void);
void MENU_SELECTOR(void);

unsigned char get_hex_part(unsigned char hex, unsigned char n);
char get_poly_power(DWORD poly);
DWORD poly_multiply(DWORD p1, DWORD p2);
DWORD poly_divide(DWORD p1, DWORD p2);
unsigned char galua_multiply(DWORD p1, DWORD p2);

void do_random_init(void);
unsigned char get_random_byte(void);
void do_generate_random_key(unsigned char new_key[][Nk]);

void read_state(const unsigned char src[], unsigned char dest[][Nb]);
void read_key(const unsigned char src[], unsigned char dest[][Nk]);
void write_state(unsigned char src[][Nb], unsigned char dest[]);
void write_key(unsigned char src[][Nk], unsigned char dest[]);

unsigned char byte_read_state(unsigned char byte[]);
unsigned char byte_write_state(unsigned char counter, unsigned char src[][Nb]);

void fill_null_state(unsigned char src[][Nb]);

void key_expansion(unsigned char cur_key[][Nk], unsigned char round);
void do_generate_round_keys(unsigned char cur_key[][Nk], unsigned char round_keys[][Nb*Nb]);
void get_round_key(unsigned char src[][Nb*Nb], unsigned char dest[][Nb], unsigned char round);
void add_round_key(unsigned char src1[][Nb], unsigned char src2[][Nb]);

void sub_bytes(unsigned char src[][Nb]);
void shift_rows(unsigned char src[][Nb]);
void mix_columns(unsigned char src[][Nb]);
void do_block_encrypt(unsigned char info_block[][Nb], unsigned char cipher_key[][Nk]);

void inv_sub_bytes(unsigned char src[][Nb]);
void inv_shift_rows(unsigned char src[][Nb]);
void inv_mix_columns(unsigned char src[][Nb]);
void do_block_decrypt(unsigned char info_block[][Nb], unsigned char cipher_key[][Nk]);


void DEMO_ROUND_KEY(void){
    unsigned char current_key[Nb][Nb];
    unsigned char i;
    read_key(in_key, key);
    printf("\n\rROUND KEY GENERATOR\n\r");
    show_key();
    write_key(key, out_32);
    printf("\n\rKey = ");
    show_out(out_32, Nk);
    printf("\n\rN rounds = ");
    printf("%i", Nr);
    printf("\n\r\n\r");
    do_generate_round_keys(key, round_keys);
    for(i=0; i<(Nr+2); i++)
    {
        get_round_key(round_keys, current_key, i);
        write_state(current_key, out_16);
        printf("Round ");
        printf("%0*i", 2, i);
        printf(": ");
        show_out(out_16, Nb);
    }
}


void DEMO_RANDOM_KEY(void){
    int code;
    do_random_init();
    printf("\n\rRANDOM KEY GENERATOR\n\r");
    Start:
    do_generate_random_key(key);
    write_key(key, out_32);
    printf("\n\rKey = ");
    show_out(out_32, Nk);
    if(code==1)
        goto Start;
}

unsigned char get_hex_part(unsigned char hex, unsigned char n){
    unsigned char result;
    switch(n){
        case 0: result=(hex&0x0F); break;
        case 1: result=(hex&0xF0)>>4; break;
        default:    result=0; break;
    }
    return result;
}
char get_poly_power(DWORD poly){
    const DWORD power[16]={0x8000, 0x4000, 0x2000, 0x1000,
                              0x0800, 0x0400, 0x0200, 0x0100,
                              0x0080, 0x0040, 0x0020, 0x0010,
                              0x0008, 0x0004, 0x0002, 0x0001};
    unsigned char i=0;
    while(!(power[i]&poly)){
        i++;
        if(i==16)
            break;
    }
    return 15-i;
}
DWORD poly_multiply(DWORD p1, DWORD p2){
    unsigned char i=0, j=0;
    DWORD poly1=p1;
    DWORD poly2=p2;
    while(get_poly_power(poly2)>-1){
        i=get_poly_power(poly2);
        if (j>0)
            poly1=((p1<<i)^poly1);
        else
            poly1=(p1<<i);
        i=trunc(pow(2, i));
        poly2=(poly2^i);
        j++;
    }
    return poly1;
}
DWORD poly_divide(DWORD p1, DWORD p2){
    DWORD poly1=p1;
    DWORD poly2=p2;
    while((get_poly_power(poly1)-get_poly_power(poly2))>-1)
        poly1=(poly1^(poly2<<(get_poly_power(poly1)-get_poly_power(poly2))));
    return poly1;
}
unsigned char galua_multiply(DWORD p1, DWORD p2){
    const DWORD m=0x11B;
    return poly_divide(poly_multiply(p1, p2), m);
}

void do_random_init(void){
    srand(time(NULL));
}
unsigned char get_random_byte(void){
    unsigned char hi, lo;
    hi=(rand()%16)<<4;
    lo=rand()%16;
    hi=hi+lo;
    return hi;
}
void do_generate_random_key(unsigned char new_key[][Nk]){
    unsigned char i, j, k;
    for(k=0; k<(Nb*Nk); k++)
    {
        j=trunc(k/Nb);
        i=k-j*Nb;
        new_key[i][j]=get_random_byte();
    }
}

void read_state(const unsigned char src[], unsigned char dest[][Nb]){
    unsigned char i, j, k;
    for(k=0; k<(Nb*Nb); k++)
    {
        j=trunc(k/Nb);
        i=k-j*Nb;
        dest[i][j]=src[k];
    }
    
}
void read_key(const unsigned char src[], unsigned char dest[][Nk]){
    unsigned char i, j, k;
    for(k=0; k<(Nb*Nk); k++)
    {
        j=trunc(k/Nb);
        i=k-j*Nb;
        dest[i][j]=src[k];
    }
    
}
void write_state(unsigned char src[][Nb], unsigned char dest[]){
    unsigned char i, j, k;
    for(j=0; j<Nb; j++)
        for(i=0; i<Nb; i++)
        {
            k=j*Nb+i;
            dest[k]=src[i][j];
        }
    
}
void write_key(unsigned char src[][Nk], unsigned char dest[]){
    unsigned char i, j, k;
    for(j=0; j<Nk; j++)
        for(i=0; i<Nb; i++)
        {
            k=j*Nb+i;
            dest[k]=src[i][j];
        }
   
}

unsigned char byte_read_state(unsigned char byte[]){
    unsigned char i, j;
    j=trunc(state_read_bytes_counter/Nb);
    i=state_read_bytes_counter-j*Nb;
    state[i][j]=byte[state_read_bytes_counter];
    if(state_read_bytes_counter!=15)
    {
        state_read_bytes_counter++;
        return 0;
    }
    else
    {
        state_read_bytes_counter=0;
        return 1;
    }
 
}
unsigned char byte_write_state(unsigned char counter, unsigned char src[][Nb]){
    unsigned char i, j;
    j=trunc(counter/Nb);
    i=counter-j*Nb;
    return src[i][j];
    
}

void fill_null_state(unsigned char src[][Nb]){
    unsigned char i, j;
    for(j=0; j<Nb; j++)
        for(i=0; i<Nb; i++)
            src[i][j]=0;
    
}

void key_expansion(unsigned char cur_key[][Nk], unsigned char round){
    const unsigned char rcon[Nb][Nr]={{0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D},
                                {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
                                {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
                                {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};

    const unsigned char sbox[16][16]={{0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
                                {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
                                {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
                                {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
                                {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
                                {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
                                {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
                                {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
                                {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
                                {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
                                {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
                                {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
                                {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
                                {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
                                {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
                                {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}};
    unsigned char r_key[Nb][Nk];
    unsigned char i, j, x, y;

    for(i=0; i<Nb; i++)
        r_key[i][0]=cur_key[i][Nk-1];
    x=r_key[0][0];
    for(i=0; i<(Nb-1); i++)
        r_key[i][0]=r_key[i+1][0];
    r_key[Nb-1][0]=x;
    for(i=0; i<Nb; i++)
    {
        x=get_hex_part(r_key[i][0], 1);
        y=get_hex_part(r_key[i][0], 0);
        r_key[i][0]=sbox[x][y];
    }
    for (i=0; i<Nb; i++)
        r_key[i][0]=r_key[i][0]^cur_key[i][0];
    for(i=0; i<Nb; i++)
        r_key[i][0]=r_key[i][0]^rcon[i][round];
    for(i=0; i<Nb; i++)
        for(j=1; j<4; j++)
            r_key[i][j]=r_key[i][j-1]^cur_key[i][j];
    for(i=0; i<Nb; i++)
        r_key[i][4]=r_key[i][3];
    for(i=0; i<Nb; i++)
    {
        x=get_hex_part(r_key[i][4], 1);
        y=get_hex_part(r_key[i][4], 0);
        r_key[i][4]=sbox[x][y];
    }
    for (i=0; i<Nb; i++)
        r_key[i][4]=r_key[i][4]^cur_key[i][4];
    for(i=0; i<Nb; i++)
        for(j=5; j<Nk; j++)
            r_key[i][j]=r_key[i][j-1]^cur_key[i][j];
    for(i=0; i<Nb; i++)
        for(j=0; j<Nk; j++)
            cur_key[i][j]=r_key[i][j];
}
void do_generate_round_keys(unsigned char cur_key[][Nk], unsigned char round_keys[][Nb*Nb]){
    unsigned char i, j, k;
    write_key(cur_key, out_32);
    for(j=0; j<(Nb*Nk); j++)
    {
        if(j<=15)
            round_keys[0][j]=out_32[j];
        else
            round_keys[1][j-16]=out_32[j];
    }
    i=2;
    for(k=0; k<trunc(Nr/2); k++)
    {
        key_expansion(cur_key, k);
        write_key(cur_key, out_32);
        for(j=0; j<(Nb*Nk); j++)
        {
            if(j<=(Nr+1))
                round_keys[i][j]=out_32[j];
            else
                round_keys[i+1][j-16]=out_32[j];
        }
        if(i<Nr)
            i+=2;
    }
}
void get_round_key(unsigned char src[][Nb*Nb], unsigned char dest[][Nb], unsigned char round){
    unsigned char i, j, k;
    for(j=0; j<Nb; j++)
        for(i=0; i<Nb; i++)
        {
            k=j*Nb+i;
            dest[i][j]=src[round][k];
        }
}
void add_round_key(unsigned char src1[][Nb], unsigned char src2[][Nb]){
    unsigned char i, j;
    for (i=0; i<Nb; i++)
        for (j=0; j<Nb; j++)
            src1[i][j]=src1[i][j]^src2[i][j];
}

void sub_bytes(unsigned char src[][Nb]){
    const unsigned char sbox[16][16]={{0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
                                {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
                                {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
                                {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
                                {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
                                {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
                                {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
                                {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
                                {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
                                {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
                                {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
                                {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
                                {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
                                {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
                                {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
                                {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}};
    unsigned char i, j, x, y;
    for(i=0; i<Nb; i++)
        for(j=0; j<Nb; j++)
        {
            x=get_hex_part(src[i][j], 1);
            y=get_hex_part(src[i][j], 0);
            src[i][j]=sbox[x][y];
        }
}
void shift_rows(unsigned char src[][Nb]){
    unsigned char i, j, k, x;
    for(i=1; i<Nb; i++)
        for(k=0; k<i; k++)
        {
            x=src[i][0];
            for(j=0; j<Nb; j++)
                src[i][j]=src[i][j+1];
            src[i][Nb-1]=x;
        }
}
void mix_columns(unsigned char src[][Nb]){
    const unsigned char gfa[4][4]={{0x02, 0x03, 0x01, 0x01},
                             {0x01, 0x02, 0x03, 0x01},
                             {0x01, 0x01, 0x02, 0x03},
                             {0x03, 0x01, 0x01, 0x02}};
    unsigned char i, j, k, tmp;
    unsigned char col[4];
    tmp=0;
    for(j=0; j<Nb; j++)
    {
        for(i=0; i<Nb; i++)
            col[i]=src[i][j];
        for(i=0; i<Nb; i++)
        {
            for(k=0; k<Nb; k++)
                if(k==0)
                    tmp=galua_multiply(col[k], gfa[i][k]);
                else
                    tmp=tmp^galua_multiply(col[k], gfa[i][k]);
            src[i][j]=tmp;
        }
    }
}
void do_block_encrypt(unsigned char info_block[][Nb], unsigned char cipher_key[][Nk]){
    unsigned char current_key[Nb][Nb];
    unsigned char i;
    do_generate_round_keys(cipher_key, round_keys);
    get_round_key(round_keys, current_key, 0);
    add_round_key(info_block, current_key);
    for(i=1; i<(Nr+1); i++)
    {
        sub_bytes(info_block);
        shift_rows(info_block);
        if(i!=Nr)
            mix_columns(info_block);
        get_round_key(round_keys, current_key, i);
        add_round_key(info_block, current_key);
    }
}

void inv_sub_bytes(unsigned char src[][Nb]){
    const unsigned char sbox[16][16]={{0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB},
                                {0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB},
                                {0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E},
                                {0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25},
                                {0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92},
                                {0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84},
                                {0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06},
                                {0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B},
                                {0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73},
                                {0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E},
                                {0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B},
                                {0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4},
                                {0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F},
                                {0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF},
                                {0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61},
                                {0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D}};
    unsigned char i, j, x, y;
    for(i=0; i<Nb; i++)
        for(j=0; j<Nb; j++)
        {
            x=get_hex_part(src[i][j], 1);
            y=get_hex_part(src[i][j], 0);
            src[i][j]=sbox[x][y];
        }
}
void inv_shift_rows(unsigned char src[][Nb]){
    unsigned char i, j, k, x;
    for(i=1; i<Nb; i++)
        for(k=0; k<i; k++)
        {
            x=src[i][Nb-1];
            for(j=Nb-1; j>0; j--)
                src[i][j]=src[i][j-1];
            src[i][0]=x;
        }
}
void inv_mix_columns(unsigned char src[][Nb]){
    const unsigned char gfa[4][4]={{0x0E, 0x0B, 0x0D, 0x09},
                             {0x09, 0x0E, 0x0B, 0x0D},
                             {0x0D, 0x09, 0x0E, 0x0B},
                             {0x0B, 0x0D, 0x09, 0x0E}};
    unsigned char i, j, k, tmp;
    unsigned char col[4];
    tmp=0;
    for(j=0; j<Nb; j++)
    {
        for(i=0; i<Nb; i++)
            col[i]=src[i][j];
        for(i=0; i<Nb; i++)
        {
            for(k=0; k<Nb; k++)
                if(k==0)
                    tmp=galua_multiply(col[k], gfa[i][k]);
                else
                    tmp=tmp^galua_multiply(col[k], gfa[i][k]);
            src[i][j]=tmp;
        }
    }
}
void do_block_decrypt(unsigned char info_block[][Nb], unsigned char cipher_key[][Nk]){
    unsigned char current_key[Nb][Nb];
    char i;
    do_generate_round_keys(cipher_key, round_keys);
    get_round_key(round_keys, current_key, Nr);
    add_round_key(info_block, current_key);
    for(i=(Nr-1); i>-1; i--)
    {
        inv_shift_rows(info_block);
        inv_sub_bytes(info_block);
        get_round_key(round_keys, current_key, i);
        add_round_key(info_block, current_key);
        if(i!=0)
            inv_mix_columns(info_block);
    }
}
//
//
//
//
//
//
//
//
//
int is_dir(char * file_path){


       struct stat s;
        if( stat(file_path,&s) == 0 )
        {
            if( s.st_mode & S_IFDIR )
            {
                //it's a directory
                return 1;

                /*encryption, if the source is a folder, the utility
will recurse into the folder and will encrypt all the files within that folder back to back generating a
single output encrypted archive.*/

            }
            else if( s.st_mode & S_IFREG )
            {
                //it's a file
                return 0;
            }
            else
            {
                //something else
                return 0;
            }
        }
        else
        {
            //error
            return 0;
        }
}

void decrypt(char * file_path,char * out_path){

        time_t start_seconds; 
        time(&start_seconds);

        FILE * fp = fopen(file_path,"rb");
        FILE * fp_out = fopen(out_path,"ab+");


        fseek(fp, 0L, SEEK_END);
        int sz = ftell(fp);

         

        fseek(fp, 0L, SEEK_SET);


        int counter=0;
        int okunan_char;
        do{
            if( ( counter % 16*16 ) == 0) printf("\r%.2f%% completed", ((double)counter/(double)sz)*100); 

            memset(in_state,0,Nb*Nb);

            okunan_char = fread(in_state,sizeof(unsigned char),Nb*Nb,fp);
            
            if(okunan_char != 0){

                
                DEMO_DECRYPT();

                fwrite(state,sizeof(unsigned char),Nb*Nb,fp_out);

            }
            
            counter += 16;
        }while(okunan_char == Nb*Nb);

        printf("\r100.00%% completed");

        time_t finish_seconds; 
   
        // Stores time seconds 
        time(&finish_seconds);

        printf("\nGecen Sure : %d" , finish_seconds - start_seconds);

        fclose(fp_out);
        fclose(fp);
}



void crypt(char * file_path,char * out_path){

        time_t start_seconds; 
        time(&start_seconds);

        FILE * fp = fopen(file_path,"rb");
        FILE * fp_out = fopen(out_path,"ab+");


        fseek(fp, 0L, SEEK_END);
        int sz = ftell(fp);

         

        fseek(fp, 0L, SEEK_SET);


        int counter=0;
        int okunan_char;
        do{
            if( ( counter % 16*16 ) == 0) printf("\r%.2f%% completed", ((double)counter/(double)sz)*100); 

            memset(in_state,0,Nb*Nb);

            okunan_char = fread(in_state,sizeof(unsigned char),Nb*Nb,fp);
            
            if(okunan_char != 0){


                DEMO_ENCRYPT();

                fwrite(state,sizeof(unsigned char),Nb*Nb,fp_out);

            }
            
            counter += 16;
        }while(okunan_char == Nb*Nb);

        printf("\r100.00%% completed");

        time_t finish_seconds; 
   
        // Stores time seconds 
        time(&finish_seconds);

        printf("\nGecen Sure : %d" , finish_seconds - start_seconds);

        fclose(fp_out);
        fclose(fp);
}


int main(void){


    char file_path[MAX_PATH];
    char output_path[MAX_PATH];
    
    printf("1 for Encryption, 0 for Decryption\n");

    int en_dec=0;
    scanf("%d\n",&en_dec);

    // wide char -> 2 byte  , char -> byte 
    // char olarak kabul edildi.

    
    gets(file_path);
    gets(output_path);

    gets((char*)in_key);

    
    if(en_dec){ // encryption

 


        struct stat s;
        if( stat(file_path,&s) == 0 )
        {
            if( s.st_mode & S_IFDIR )
            {
                //it's a directory


                DIR *dir;
                struct dirent *dp;
                char * file_name;
                dir = opendir(file_path);

                while ((dp=readdir(dir)) != NULL) {
                    
                    file_name = dp->d_name;

                    

                    if(!is_dir(file_name)) {

                        char buffer[MAX_PATH];
                        memset(buffer,0,MAX_PATH);

                        strcat(buffer,file_path);
                        strcat(buffer,"\\");
                        strcat(buffer,file_name);

                        
                        crypt(buffer,output_path);
                        
                        
                        }

                }
                
                closedir(dir);


            }
            else if( s.st_mode & S_IFREG )
            {
                //it's a file

                crypt(file_path,output_path);
                
            }

        }




    }else{ // decryption


        

        decrypt(file_path,output_path);




    }


  

    return 0;
}


void DEMO_ENCRYPT(void){

    read_key(in_key, key);
    read_state(in_state, state);
    //printf("\n\rENCRYPT\n\r");
    //show_state();
    write_state(state, out_16);
    //printf("\n\rState = ");
    //show_out(out_16, Nb);
    //show_key();
    write_key(key, out_32);
    //printf("\n\rKey = ");
    //show_out(out_32, Nk);
    do_block_encrypt(state, key);
    //show_state();
    write_state(state, out_16);
    //printf("\n\rState = ");
    //show_out(out_16, Nb);
}
void DEMO_DECRYPT(void){
    read_key(in_key, key);
    read_state(in_cipher, state);
    //printf("\n\rDECRYPT\n\r");
    //show_state();
    write_state(state, out_16);
    //printf("\n\rState = ");
    //show_out(out_16, Nb);
    //show_key();
    write_key(key, out_32);
    //printf("\n\rKey = ");
    //show_out(out_32, Nk);
    do_block_decrypt(state, key);
    //show_state();
    write_state(state, out_16);
    //printf("\n\rState = ");
    //show_out(out_16, Nb);
}
