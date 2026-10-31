
ulong ssl_crypto_x509_session_verify_cert_chain(long param_1,long *param_2,undefined1 *param_3)

{
  long *plVar1;
  long lVar2;
  long lVar3;
  undefined8 uVar4;
  undefined1 uVar5;
  int iVar6;
  long lVar7;
  long lVar8;
  ulong uVar9;
  char *pcVar10;
  undefined8 uVar11;
  long lVar12;
  long lVar13;
  long local_38;
  
  if (*(char *)(param_1 + 0x1b0) == '\0') {
    *param_3 = 0x50;
    plVar1 = *(long **)(param_1 + 0xa0);
    if ((plVar1 != (long *)0x0) && (*plVar1 != 0)) {
      lVar8 = *param_2;
      lVar2 = *(long *)(lVar8 + 0x68);
      lVar13 = *(long *)(*(long *)(lVar8 + 0x30) + 0x118);
      uVar11 = 0;
      if (lVar13 == 0) {
         lVar12 = 0;
      }
      else {
         lVar12 = 0;
         uVar11 = 0;
         if ((*(byte *)(lVar8 + 0xa4) & 1) == 0) {
           uVar11 = 0;
           lVar12 = 0;
           if (*(int *)(*(long *)(lVar8 + 0x30) + 0xd8) == 2) {
             lVar13 = *(long *)(lVar13 + 0x818);
             uVar11 = *(undefined8 *)(lVar13 + 0x20);
             lVar12 = *(long *)(lVar13 + 0x28);
           }
         }
      }
      lVar13 = *(long *)(lVar2 + 0x68);
      lVar3 = *(long *)(*(long *)(param_2[1] + 0x20) + 0x60);
      uVar4 = *(undefined8 *)plVar1[1];
      lVar7 = FUN_00938f99();
      local_38 = lVar7;
      if (lVar7 == 0) {
LAB_00958114:
         FUN_00912ac0(0x10,0xb,"../../../flutter/third_party/boringssl/src/ssl/ssl_x509.cc",0xf3);
LAB_0095812b:
         uVar9 = 0;
      }
      else {
         if (lVar3 != 0) {
           lVar13 = lVar3;
         }
         iVar6 = FUN_00939017(lVar7,lVar13,uVar4,plVar1);
         if (iVar6 == 0) goto LAB_00958114;
         iVar6 = FUN_009209a9(lVar7 + 0x70,0,lVar8);
         if (iVar6 == 0) goto LAB_00958114;
         pcVar10 = "ssl_server";
         if ((*(byte *)(lVar8 + 0xa4) & 1) != 0) {
           pcVar10 = "ssl_client";
         }
         lVar8 = FUN_0093952f(pcVar10);
         if (lVar8 == 0) goto LAB_00958114;
         iVar6 = FUN_0093913c(*(undefined8 *)(lVar7 + 0x20),lVar8);
         if (iVar6 == 0) goto LAB_00958114;
         iVar6 = FUN_00939143(*(undefined8 *)(lVar7 + 0x20),*(undefined8 *)(param_2[1] + 0x10),1);
         if (iVar6 == 0) goto LAB_00958114;
         if (lVar12 != 0) {
           iVar6 = FUN_00939474(*(undefined8 *)(lVar7 + 0x20),uVar11,lVar12);
           if (iVar6 == 0) goto LAB_00958114;
         }
         if (*(long *)(param_2[1] + 0x28) != 0) {
           *(long *)(lVar7 + 0x30) = *(long *)(param_2[1] + 0x28);
         }
         if (*(code **)(lVar2 + 0xb8) == (code *)0x0) {
           iVar6 = FUN_00935a9b(lVar7);
         }
         else {
           iVar6 = (**(code **)(lVar2 + 0xb8))(lVar7,*(undefined8 *)(lVar2 + 0xc0));
         }
         lVar8 = (long)*(int *)(lVar7 + 0x4c);
         *(long *)(param_1 + 0xb0) = lVar8;
         if ((iVar6 < 1) && (*(char *)(param_2[1] + 0x148) != '\0')) {
           uVar5 = 0x2e;
           if (lVar8 - 1U < 0x42) {
             uVar5 = *(undefined1 *)(&DAT_003a324c + lVar8 * 2);
           }
           *param_3 = uVar5;
           goto LAB_0095812b;
         }
         FUN_00912a61();
         uVar9 = CONCAT71((int7)((ulong)lVar7 >> 8),1);
      }
      FUN_00957a52(&local_38);
      goto LAB_00957f6e;
    }
  }
  uVar9 = 0;
LAB_00957f6e:
  return uVar9 & 0xffffffff;
}

