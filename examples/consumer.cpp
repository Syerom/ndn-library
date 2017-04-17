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
#include <iostream>
#include <cryptopp/base64.h>
#include <cryptopp/sha.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <cryptopp/hex.h>

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
    std::string str5=std::string(this->SHA256Generation(str1.append(str2))).substr(0,32);
    std::string str6=std::string(this->SHA256Generation(str3.append(str4))).substr(0,32);
    // A token
    std::string Atoken = std::string(this->SHA256Generation("M0419169MASTERKEY")).substr(0,32);
    // hashvalidation
    hashValidation = std::string(this->SHA256Generation(str5.append(str6))).substr(0,32);



    Interest interest(Name("/A/testApp/file.pdf"));
    interest.setInterestLifetime(time::milliseconds(1000));
    interest.setMustBeFresh(true);
    interest.setNonce(0);
    // Set the value of new fields
    std::ostringstream os;
    os<< interest.getNonce();
    hashValidation=std::string(this->SHA256Generation(Atoken.append(hashValidation).append(os.str()))).substr(0,32);
    
    interest.setHashValidation((char*)hashValidation.c_str());
    interest.setSID((char*)SID.c_str());
    interest.setRoleName((char*)RoleName.c_str());

    m_face.expressInterest(interest,
                           bind(&Consumer::onData, this,  _1, _2),
                           bind(&Consumer::onNack, this, _1, _2),
                           bind(&Consumer::onTimeout, this, _1));

    std::cout << "Sending " << interest << std::endl;

    // processEvents will block until the requested data received or timeout occurs
    m_face.processEvents();

  }

private:
  void
  onData(const Interest& interest, const Data& data)
  { 
    std::cout << data << std::endl;
    //std::cout << "Content: " << readString(data.getContent()) << "\n";

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
  ndn::examples::Consumer consumer;
  try {
    consumer.run();
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
  }
  return 0;
}
