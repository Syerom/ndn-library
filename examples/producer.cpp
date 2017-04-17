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
    static const std::string SID = "M000001";
    static const std::string RoleName = "Engineer";
    static const std::string hashValidation = "TestHashValidation";

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

      if (std::string(interest.getHashValidation())!= hashValidation)
      {
        std::string reason = "Hash Token Failed";
        this->onRegisterFail(interest.getName(),reason,1);
        lp::Nack nack(interest);
        m_face.put(nack);
      } else {
        // Create new name, based on Interest's name
        Name dataName(interest.getName());
        dataName
          .append("testApp"); // add "testApp" component to Interest name
        //.appendVersion();  // add "version" component (current UNIX timestamp in milliseconds)

        static const std::string content = "HELLO KITTY, by Mocca";

        // Create Data packet
        shared_ptr<Data> data = make_shared<Data>();
        data->setName(dataName);
        data->setFreshnessPeriod(time::seconds(10));
        data->setContent(reinterpret_cast<const uint8_t*>(content.c_str()), content.size());

        // Sign Data packet with default identity
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

private:
  Face m_face;
  KeyChain m_keyChain;
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
