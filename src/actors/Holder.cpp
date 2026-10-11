#include "actors/Holder.h"
//Tạo holder:
Holder::Holder(const DID& did) :
	did(did)
{
}

//Lấy DID của Holder:
const DID& Holder::getDID() const
{
	return did; 
}
//Holder nhận VC
void Holder::receiveCredential(
	const VerifiableCredential& credential)
{
	credentials.push_back(credential);
}
//Lưu VC vào danh sách
const std::vector<VerifiableCredential>&
Holder::getCredentials() const
{
	return credentials;
}
//Tìm VC theo ID
for (const auto& credential : credentials)
{
	if (credential.getId() == credentialId)
	{
		return &credential;
	}
}
const VerifiableCredential*
Holder::findCredential(const std::string& credentialId) const
{
	for (const auto& credential : credentials)
	{
		if (credential.getId() == credentialId)
		{
			return &credential;
		}
	}
	return nullptr;
}

/******************************************************************************

Welcome to GDB Online.
  GDB online is an online compiler and debugger tool for C, C++, Python, PHP, Ruby, 
  C#, OCaml, VB, Perl, Swift, Prolog, Javascript, Pascal, COBOL, HTML, CSS, JS
  Code, Compile, Run and Debug online from anywhere in world.

*******************************************************************************/
#include <stdio.h>

int main()
{
    int gt1, gt2;
    gt1 = (2*3+4/2 > 3)&&(3<5)||(10<9);
    gt2 = (5+9*3^2 - 4 > 10)&&((2+2^4-8/4>6)||(2<6&&10>11));
    printf("Gia tri 1 la: %d\n", gt1);
    printf("Gia tri 2 la: %d\n", gt2);
    return 0;
}