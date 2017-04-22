/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2013-2016 Regents of the University of California.
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
#include "face.hpp"
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
#include <stdio.h>
#include <stdlib.h>


// Enclosing code in ndn simplifies coding (can also use `using namespace ndn`)
namespace ndn {
// Additional nested namespace could be used to prevent/limit name contentions
namespace examples {

class Consumer : noncopyable
{
public:
  void
  run()
  { 
    // MHT left child
    // Nameing prefix
    std::string str1=std::string(this->SHA256Generation(std::string("/A/testApp"))).substr(0,32);
    // File name
    std::string str2=std::string(this->SHA256Generation(std::string("/file.pdf"))).substr(0,32);
    // MHT right child
    // Role name
    std::string str3=std::string(this->SHA256Generation(RoleName)).substr(0,32);
    // Attribute
    std::string str4=std::string(this->SHA256Generation(std::string("permissionsalarydeployment"))).substr(0,32);
    // MHT computation
    //std::chrono::steady_clock::time_point startTime = std::chrono::steady_clock::now();

    std::string str5=std::string(this->SHA256Generation(str1.append(str2))).substr(0,32);
    std::string str6=std::string(this->SHA256Generation(str3.append(str4))).substr(0,32);
    // A token
    std::string Atoken = std::string(this->SHA256Generation("M0419169MASTERKEY")).substr(0,32);
    // hashvalidation
    hashValidation = std::string(this->SHA256Generation(str5.append(str6))).substr(0,32);



    Interest interest(Name("/A/testApp/file.pdf"));
    interest.setInterestLifetime(time::milliseconds(1000));
    interest.setMustBeFresh(true);
    int ran= rand()%100000+1;
    interest.setNonce(ran);
    // Set the value of new fields
    std::ostringstream os;
    os<< interest.getNonce();
    hashValidation=std::string(this->SHA256Generation(Atoken.append(hashValidation).append(os.str()))).substr(0,32);
    os.str()="";
    os.clear();

    interest.setHashValidation((char*)hashValidation.c_str());
    interest.setSID((char*)SID.c_str());
    interest.setRoleName((char*)RoleName.c_str());
    std::cout << interest.getHashValidation() << std::endl;

    //std::chrono::steady_clock::time_point startTime = std::chrono::steady_clock::now();

    m_face.expressInterest(interest,
                           bind(&Consumer::onData, this,  _1, _2),
                           bind(&Consumer::onNack, this, _1, _2),
                           bind(&Consumer::onTimeout, this, _1));


    //writeToCSV(std::chrono::duration_cast<std::chrono::microseconds>(endTime-startTime).count(),std::string("./data/clientProcessDelay.csv"));

    std::cout << "Sending " << interest << std::endl;
    std::cout << std::endl;

    // processEvents will block until the requested data received or timeout occurs
    //std::chrono::steady_clock::time_point startTime = std::chrono::steady_clock::now();

    m_face.processEvents();
   //std::chrono::steady_clock::time_point endTime = std::chrono::steady_clock::now();
   //std::cout<< std::chrono::duration_cast<std::chrono::microseconds>(endTime-startTime).count()<<"us"<<std::endl;
  }

private:
  void
  onData(const Interest& interest, const Data& data)
  { 
    //std::chrono::steady_clock::time_point startTime = std::chrono::steady_clock::now();
    std::cout << data << std::endl;
    std::cout << "Content: " << AESDecrypt(readString(data.getContent())) << "\n";
    // std::chrono::steady_clock::time_point endTime = std::chrono::steady_clock::now();
    // std::cout<< std::chrono::duration_cast<std::chrono::microseconds>(endTime-startTime).count()<<"us"<<std::endl;
    // writeToCSV(std::chrono::duration_cast<std::chrono::microseconds>(endTime-startTime).count(),std::string("./data/clientOnDataDelay1.csv"));
  }

  void
  onNack(const Interest& interest, const lp::Nack& nack)
  {
    std::cout << "received Nack with reason " << nack.getReason()
              << " for interest " << interest << std::endl;
  }

  void
  onTimeout(const Interest& interest)
  {
    std::cout << "Timeout " << interest << std::endl;
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
  AESDecrypt(std::string cipherText)
  {
    byte key[CryptoPP::AES::DEFAULT_KEYLENGTH], iv[CryptoPP::AES::BLOCKSIZE];
    memset(key,0x00,CryptoPP::AES::DEFAULT_KEYLENGTH);
    memset(iv,0x00,CryptoPP::AES::BLOCKSIZE);

    std::string decryptText;
    
    CryptoPP::AES::Decryption aesDecryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption( aesDecryption, iv );
    CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink( decryptText ));
    stfDecryptor.Put( reinterpret_cast<const unsigned char*>( cipherText.c_str() ), cipherText.size());
    stfDecryptor.MessageEnd();
    return decryptText;
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
  std::string SID = std::string("M000001");
  std::string RoleName = std::string("Engineer");
  std::string hashValidation ;
};

} // namespace examples
} // namespace ndn

int
main(int argc, char** argv)
{
  srand(time(NULL));

  try {
      int flag=1;
      while(flag<=1){
      ndn::examples::Consumer consumer;
      consumer.run();
        flag++;
      }
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
  }
  return 0;
}
