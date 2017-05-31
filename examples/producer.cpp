/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2013-2015 Regents of the University of California.
 *
 * This file is part of ndn-cxx library (NDN C++ library with eXperimental eXtensions).
 *
 * ndn-cxx library is free software: you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * ndn-cxx library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received copies of the GNU General Public License and GNU Lesser
 * General Public License along with ndn-cxx, e.g., in COPYING.md file.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of ndn-cxx authors and contributors.
 *
 * @author Alexander Afanasyev <http://lasr.cs.ucla.edu/afanasyev/index.html>
 */

// correct way to include ndn-cxx headers
// #include <ndn-cxx/face.hpp>
// #include <ndn-cxx/security/key-chain.hpp>

#include "face.hpp"
#include "security/key-chain.hpp"

#include <time.h>
#include <chrono>
#include <iostream>
#include <cryptopp/base64.h>
#include <cryptopp/sha.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <cryptopp/hex.h>
#include <fstream>


// Enclosing code in ndn simplifies coding (can also use `using namespace ndn`)
namespace ndn {
// Additional nested namespace could be used to prevent/limit name contentions
namespace examples {

class Producer : noncopyable
{
public:
  void
  run()
  {
    m_face.setInterestFilter("/A/testApp",
                             bind(&Producer::onInterest, this, _1, _2),
                             RegisterPrefixSuccessCallback(),
                             bind(&Producer::onRegisterFailed, this, _1, _2));
    m_face.processEvents();
  }

private:
  void
  onInterest(const InterestFilter& filter, const Interest& interest)
  {
    // // MHT left child
    // // Nameing prefix
    // std::string str1=std::string(this->SHA256Generation(std::string("/A/testApp"))).substr(0,32);
    // // File name
    // std::string str2=std::string(this->SHA256Generation(std::string("/file.pdf"))).substr(0,32);
    // // MHT right child
    // // Role name
    // std::string str3=std::string(this->SHA256Generation(std::string(interest.getRoleName()))).substr(0,32);
    // // Attribute
    // std::string str4=std::string(this->SHA256Generation(std::string("permissionsalarydeployment"))).substr(0,32);
    // // MHT computation
    // //std::chrono::steady_clock::time_point startTime = std::chrono::steady_clock::now();

    // std::string str5=std::string(this->SHA256Generation(str1.append(str2))).substr(0,32);
    // std::string str6=std::string(this->SHA256Generation(str3.append(str4))).substr(0,32);
    // // A token
    // std::string Atoken = std::string(this->SHA256Generation("M0419169MASTERKEY")).substr(0,32);
    // // hashvalidation
    // hashValidation = std::string(this->SHA256Generation(str5.append(str6))).substr(0,32);

    std::string r = "10";
    hashValidation = std::string(this->SHA256Generation(r.append(RoleName).append("M0419169MASTERKEY"))).substr(0,32);

    std::ostringstream os;
    os<< interest.getNonce();
    hashValidation=std::string(this->SHA256Generation(hashValidation.append(os.str()))).substr(0,32);
    os.str()="";
    os.clear();

    std::cout << "<< I: " << interest << std::endl;
    std::cout << "HashValidation: " << interest.getHashValidation() << std::endl;
    std::cout << "SID: " << interest.getSID() << std::endl;
    std::cout << "Role Name: " << interest.getRoleName() << std::endl;

    // check RoleName and SID
    if (std::string(interest.getRoleName()) != RoleName ||
        std::string(interest.getSID()) != SID)
    {
      std::string reason="Permission Denied";
      this->onRegisterFail(interest.getName(),reason,1);
      lp::Nack nack(interest);
      m_face.put(nack);
    } else {
      // check hash validation
      if (std::string(interest.getHashValidation())!= hashValidation)
      {
        std::string reason = "Hash Token Failed";
        lp::Nack nack(interest);
        m_face.put(nack);
        this->onRegisterFail(interest.getName(),reason,1);
        //std::chrono::steady_clock::time_point endTime = std::chrono::steady_clock::now();
        //std::cout<< std::chrono::duration_cast<std::chrono::microseconds>(endTime-startTime).count()<<"us"<<std::endl;
        //writeToCSV(std::chrono::duration_cast<std::chrono::microseconds>(endTime-startTime).count(),std::string("./data/serverFailDelay.csv"));
      } else {
        // Create new name, based on Interest's name
        Name dataName(interest.getName());
        dataName
          .append("testApp"); // add "testApp" component to Interest name
        //.appendVersion();  // add "version" component (current UNIX timestamp in milliseconds)

        static const std::string content = AESEncrypt("HELLO KITTY, by Mocca");

        // Create Data packet
        shared_ptr<Data> data = make_shared<Data>();
        data->setName(dataName);
        data->setFreshnessPeriod(time::seconds(10));
        data->setContent(reinterpret_cast<const uint8_t*>(content.c_str()), content.size());

        // Sign Data packet with default identity
        //std::chrono::steady_clock::time_point startTime = std::chrono::steady_clock::now();
        m_keyChain.sign(*data);

        
        // m_keyChain.sign(data, <identityName>);
        // m_keyChain.sign(data, <certificate>);

        // Return Data packet to the requester
        std::cout << ">> D: " << *data << std::endl;
        m_face.put(*data);
      }
     } 
  }

  void
  onRegisterFailed(const Name& prefix, const std::string& reason)
  {
    std::cout << "ERROR: Failed to register prefix \""
              << prefix << "\" in local hub's daemon (" << reason << ")"
              << std::endl;
    m_face.shutdown();
  }

  void
  onRegisterFail(const Name& prefix, const std::string& reason, const int failType)
  {
    switch(failType){
      case 1:
              std::cerr << "ERROR: Failed to register prefix \""
              << prefix << "\" in local hub's daemon (" << reason << ")"
              << std::endl;
              break;
      default:
              break;
    }
     //m_face.shutdown();
  }

  char*
  SHA256Generation(std::string str)
  {
    byte digest[CryptoPP::SHA256::DIGESTSIZE];
    CryptoPP::SHA256().CalculateDigest(digest, (byte*) &str[0], str.size());
    std::string ret;
    CryptoPP::HexEncoder encoder;
    encoder.Attach(new CryptoPP::StringSink(ret));
    encoder.Put(digest, sizeof(digest));
    encoder.MessageEnd();
    
    return (char*)ret.c_str();
  }

  std::string
  AESEncrypt(std::string plainText)
  {
    byte key[CryptoPP::AES::DEFAULT_KEYLENGTH], iv[CryptoPP::AES::BLOCKSIZE];
    memset(key,0x00,CryptoPP::AES::DEFAULT_KEYLENGTH);
    memset(iv,0x00,CryptoPP::AES::BLOCKSIZE);

    std::string cipherText;
    CryptoPP::AES::Encryption aesEncryption(key,CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption,iv);
    CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption,
                                                    new CryptoPP::StringSink(cipherText));
    stfEncryptor.Put(reinterpret_cast<const unsigned char*>(plainText.c_str()),
                   plainText.length()+1);
    stfEncryptor.MessageEnd();
  
    return cipherText;
  }

  void writeToCSV(int time,std::string str){
    std::ofstream fp;
    //printf("haha\n");
    fp.open(str,std::ios::app);
    fp<<time<<",\t"<<std::endl;
    fp.close();
  }

private:
  Face m_face;
  KeyChain m_keyChain;
  std::string SID = std::string("M000001");
  std::string RoleName = std::string("Engineer");
  std::string hashValidation ;
};

} // namespace examples
} // namespace ndn

int
main(int argc, char** argv)
{
  ndn::examples::Producer producer;
  try {
    producer.run();
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
  }
  return 0;
}
