Description:
`I miss MySpace. Ranking my friends publicly is goated. I decided to bring it back, with new security features so we can all win!`

solution:
This is challenge where we are required to bypass the canary and get to the win function , oh so , it is quite classical.
The mitigation are only canary , pretty simple right?
By looking in the code , we can see that it is menu based , where we can,
1.List all the friends.
2.Edit the friends name.
3.Display a specific friend name.
4.quit 
`Vulnerability here:`
```

void display_friend(long param_1)

{
  int iVar1;
  long in_FS_OFFSET;
  char local_28 [24];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  puts("\nEnter index to display (0-7): ");
  fgets(local_28,16,stdin);
  iVar1 = FUN_00401160(local_28);
  if ((iVar1 < 0) || (7 < iVar1)) {
    puts("Invalid index!");
  }
  write(1,(void *)(param_1 + (long)iVar1 * 8),8);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}

```
In the display_friend function , we can see that write is being called even though it is not within the index of 0-7 , so we can calculate the offset to current start address of the friends name to the canary , which is 140 , so if we give the index as 13 , we can leak the canary.
the offset to RIP is 64 , so overwrite the RIP `get_flag` function to get the flag.

FLAG :  `idek{b4bys_1st_c00k1e_leak_yayyy!}`
