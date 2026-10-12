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
// Holder nhận và lưu VC vào danh sách, không sửa chữ ký
void Holder::receiveCredential(
	const VerifiableCredential& credential)
{
	credentials.push_back(credential);
}

// Trả danh sách VC đã lưu
const std::vector<VerifiableCredential>&
Holder::getCredentials() const
{
	return credentials;
}
//Tìm VC theo ID
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

