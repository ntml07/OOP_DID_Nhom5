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

