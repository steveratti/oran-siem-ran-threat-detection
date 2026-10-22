/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
/*
 * Scenario A (revised): resource-exhaustion UE anomaly for SIEM-side detection.
 *
 * Same deployment as the jammer dataset (jammer_gnb3.cc): 1 LTE anchor + 4 gNBs at
 * (500,500), (700,500), (400,673.2), (400,326.8), 3.5 GHz / 20 MHz, gNB 44 dBm,
 * 3GPP UMi Street Canyon, RandomWalk2dOutdoor 3-7 m/s, E2 KPM every 50 ms.
 *
 * Every UE receives benign downlink traffic with a random profile (light / medium /
 * heavy, ON/OFF). In each run nAttackers UEs, chosen at random from the RngRun seed,
 * additionally receive a constant downlink UDP flood of attackRateMbps from attackStart
 * on (DL flooding of a victim UE / compromised UE pulling traffic). All random draws
 * are made in both the attack run and the control run (anomalyOn=false), so a control
 * run with the same RngRun has identical mobility, benign traffic and "would-be"
 * attackers; only the flood is not started.
 *
 * Ground truth is written to anomaly.txt.
 *
 * Example:
 *   ./ns3 run "scenario_anomaly_ue --RngRun=7 --anomalyOn=1 --attackRateMbps=20 \
 *              --enableE2FileLogging=1 --enableTraces=0"
 *
 * Based on scenario-zero (Orange Innovation / ns-O-RAN authors, GPLv2):
 * Andrea Lacava, Michele Polese, Argha Sen, Kamil Kociszewski, Mostafa Ashraf.
 * This program is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License version 2 as published by the Free Software
 * Foundation.
 */
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/applications-module.h"
#include "ns3/point-to-point-helper.h"
#include <ns3/lte-ue-net-device.h>
#include "ns3/mmwave-helper.h"
#include "ns3/epc-helper.h"
#include "ns3/mmwave-point-to-point-epc-helper.h"
#include "../src/mmwave/model/node-container-manager.h"
#include "ns3/lte-helper.h"
#include "ns3/isotropic-antenna-model.h"
#include "ns3/mmwave-enb-phy.h"
#include "ns3/channel-condition-model.h"
#include "ns3/three-gpp-propagation-loss-model.h"
#include <sys/time.h>
#include <ctime>
#include <iostream>
#include <fstream>
#include <vector>
#include <algorithm>
#include <cmath>
#include <map>
#include <tuple>

using namespace ns3;
using namespace mmwave;

int ue_assoc_list[64] = {0};
double maxXAxis;
double maxYAxis;

NS_LOG_COMPONENT_DEFINE ("ScenarioAnomalyUe");

void
PrintGnuplottableUeListToFile (std::string filename)
{
  std::ofstream outFile (filename.c_str (), std::ios_base::out | std::ios_base::trunc);
  if (!outFile.is_open ())
    {
      return;
    }
  for (NodeList::Iterator it = NodeList::Begin (); it != NodeList::End (); ++it)
    {
      Ptr<Node> node = *it;
      for (uint32_t j = 0; j < node->GetNDevices (); j++)
        {
          Ptr<McUeNetDevice> mcuedev = node->GetDevice (j)->GetObject<McUeNetDevice> ();
          if (mcuedev)
            {
              Vector pos = node->GetObject<MobilityModel> ()->GetPosition ();
              outFile << "set label \"" << mcuedev->GetImsi () << "\" at " << pos.x << "," << pos.y
                      << " left font \"Helvetica,8\" textcolor rgb \"black\" front point pt 1 ps "
                         "0.3 lc rgb \"black\" offset 0,0"
                      << std::endl;
            }
        }
    }
}

void
PrintGnuplottableEnbListToFile (uint64_t m_startTime)
{
  uint64_t timestamp = m_startTime + (uint64_t) Simulator::Now ().GetMilliSeconds ();
  for (NodeList::Iterator it = NodeList::Begin (); it != NodeList::End (); ++it)
    {
      Ptr<Node> node = *it;
      for (uint32_t j = 0; j < node->GetNDevices (); j++)
        {
          Ptr<LteEnbNetDevice> enbdev = node->GetDevice (j)->GetObject<LteEnbNetDevice> ();
          Ptr<MmWaveEnbNetDevice> mmdev = node->GetDevice (j)->GetObject<MmWaveEnbNetDevice> ();
          if (enbdev)
            {
              Vector pos = node->GetObject<MobilityModel> ()->GetPosition ();
              std::ofstream f ("enbs.txt", std::ios_base::out | std::ios_base::app);
              f << timestamp << "," << enbdev->GetCellId () << "," << pos.x << "," << pos.y << ","
                << m_startTime << ",0,30" << std::endl;
            }
          else if (mmdev)
            {
              Vector pos = node->GetObject<MobilityModel> ()->GetPosition ();
              auto ueMap = mmdev->GetUeMap ();
              for (const auto &ue : ueMap)
                {
                  uint64_t imsi_assoc = ue.second->GetImsi ();
                  if (imsi_assoc >= 1 && imsi_assoc <= 64)
                    {
                      ue_assoc_list[imsi_assoc - 1] = mmdev->GetCellId ();
                    }
                }
              std::ofstream f ("gnbs.txt", std::ios_base::out | std::ios_base::app);
              f << timestamp << "," << mmdev->GetCellId () << "," << pos.x << "," << pos.y << ","
                << m_startTime << ",0,0,0,0" << std::endl;
            }
        }
    }
}

void
ClearFile (std::string filename, uint64_t m_startTime)
{
  uint64_t timestamp = m_startTime + (uint64_t) Simulator::Now ().GetMilliSeconds ();
  std::ofstream f (filename.c_str (), std::ios_base::out | std::ios_base::trunc);
  if (filename == "ue_position.txt")
    {
      f << "timestamp,id,x,y,type,cell,simid" << std::endl;
    }
  else
    {
      f << "timestamp,id,x,y,simid,ESstate,currEC,maxEC,totalcurrEC" << std::endl;
      f << timestamp << ",0," << maxXAxis << "," << maxYAxis << std::endl;
    }
}

void
PrintPosition (Ptr<Node> node, std::string filename, uint64_t m_startTime)
{
  uint64_t timestamp = m_startTime + (uint64_t) Simulator::Now ().GetMilliSeconds ();
  for (uint32_t j = 0; j < node->GetNDevices (); j++)
    {
      Ptr<McUeNetDevice> mcuedev = node->GetDevice (j)->GetObject<McUeNetDevice> ();
      if (mcuedev)
        {
          int imsi = int (mcuedev->GetImsi ());
          int serving_cell = (imsi >= 1 && imsi <= 64) ? ue_assoc_list[imsi - 1] : 0;
          Vector position = node->GetObject<MobilityModel> ()->GetPosition ();
          std::ofstream f (filename.c_str (), std::ios_base::out | std::ios_base::app);
          f << timestamp << "," << imsi << "," << position.x << "," << position.y << ",mc,"
            << serving_cell << "," << m_startTime << std::endl;
        }
    }
}

static ns3::GlobalValue g_bufferSize ("bufferSize", "RLC tx buffer size (MB)",
                                      ns3::UintegerValue (10), ns3::MakeUintegerChecker<uint32_t> ());
static ns3::GlobalValue g_enableTraces ("enableTraces", "If true, generate ns-3 traces",
                                        ns3::BooleanValue (true), ns3::MakeBooleanChecker ());
static ns3::GlobalValue g_e2lteEnabled ("e2lteEnabled", "If true, send LTE E2 reports",
                                        ns3::BooleanValue (true), ns3::MakeBooleanChecker ());
static ns3::GlobalValue g_e2nrEnabled ("e2nrEnabled", "If true, send NR E2 reports",
                                       ns3::BooleanValue (true), ns3::MakeBooleanChecker ());
static ns3::GlobalValue g_e2du ("e2du", "If true, send DU reports", ns3::BooleanValue (true),
                                ns3::MakeBooleanChecker ());
static ns3::GlobalValue g_e2cuUp ("e2cuUp", "If true, send CU-UP reports", ns3::BooleanValue (true),
                                  ns3::MakeBooleanChecker ());
static ns3::GlobalValue g_e2cuCp ("e2cuCp", "If true, send CU-CP reports", ns3::BooleanValue (true),
                                  ns3::MakeBooleanChecker ());
static ns3::GlobalValue g_reducedPmValues ("reducedPmValues", "If true, use a subset of the pm containers",
                                           ns3::BooleanValue (false), ns3::MakeBooleanChecker ());
static ns3::GlobalValue g_hoSinrDifference ("hoSinrDifference",
                                            "The value for which an handover between MmWave eNB is triggered",
                                            ns3::DoubleValue (0.0), ns3::MakeDoubleChecker<double> ());
static ns3::GlobalValue g_indicationPeriodicity ("indicationPeriodicity",
                                                 "E2 Indication Periodicity reports (value in seconds)",
                                                 ns3::DoubleValue (0.05),
                                                 ns3::MakeDoubleChecker<double> (0.01, 2.0));
static ns3::GlobalValue g_simTime ("simTime", "Simulation time in seconds", ns3::DoubleValue (60.0),
                                   ns3::MakeDoubleChecker<double> (0.1, 100000.0));
static ns3::GlobalValue g_outageThreshold ("outageThreshold", "SNR threshold for outage events [dB]",
                                           ns3::DoubleValue (-15.0), ns3::MakeDoubleChecker<double> ());
static ns3::GlobalValue g_numberOfRaPreambles ("numberOfRaPreambles",
                                               "how many random access preambles are available",
                                               ns3::UintegerValue (40),
                                               ns3::MakeUintegerChecker<uint8_t> ());
static ns3::GlobalValue g_handoverMode ("handoverMode", "HO euristic to be used",
                                        ns3::StringValue ("Threshold"), ns3::MakeStringChecker ());
static ns3::GlobalValue g_e2TermIp ("e2TermIp", "The IP address of the RIC E2 termination",
                                    ns3::StringValue ("127.0.0.1"), ns3::MakeStringChecker ());
static ns3::GlobalValue g_enableE2FileLogging ("enableE2FileLogging",
                                               "If true, generate offline file logging instead of connecting to RIC",
                                               ns3::BooleanValue (false), ns3::MakeBooleanChecker ());
static ns3::GlobalValue g_e2_func_id ("KPM_E2functionID", "Function ID to subscribe",
                                      ns3::DoubleValue (2), ns3::MakeDoubleChecker<double> ());
static ns3::GlobalValue g_rc_e2_func_id ("RC_E2functionID", "Function ID to subscribe",
                                         ns3::DoubleValue (3), ns3::MakeDoubleChecker<double> ());
static ns3::GlobalValue g_controlFileName ("controlFileName", "The path to the control file",
                                           ns3::StringValue (""), ns3::MakeStringChecker ());
static ns3::GlobalValue mmWave_nodes ("N_MmWaveEnbNodes", "Number of mmWaveNodes",
                                      ns3::UintegerValue (4), ns3::MakeUintegerChecker<uint8_t> ());
static ns3::GlobalValue ue_s ("N_Ues", "Number of User Equipments", ns3::UintegerValue (10),
                              ns3::MakeUintegerChecker<uint32_t> ());
static ns3::GlobalValue center_freq ("CenterFrequency", "Center Frequency Value",
                                     ns3::DoubleValue (3.5e9), ns3::MakeDoubleChecker<double> ());
static ns3::GlobalValue bandwidth_value ("Bandwidth", "Bandwidth Value", ns3::DoubleValue (20e6),
                                         ns3::MakeDoubleChecker<double> ());
static ns3::GlobalValue interside_distance_value_cell ("IntersideDistanceCells", "Interside Distance Value",
                                                       ns3::DoubleValue (200),
                                                       ns3::MakeDoubleChecker<double> ());

// ---------------- IT-domain flow log at the PGW (SGi boundary), 1 s bins ----------------
// One record per second and per (src, dst, protocol, ports) of the UE user plane, as a
// NetFlow/IPFIX exporter or firewall at the core-network boundary would report it.
static std::map<std::tuple<uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t>,
                std::pair<uint64_t, uint64_t>> g_flows;

static void
FlowLogForward (const Ipv4Header &h, Ptr<const Packet> p, uint32_t /* iface */)
{
  uint32_t src = h.GetSource ().Get ();
  uint32_t dst = h.GetDestination ().Get ();
  if ((src >> 24) != 7 && (dst >> 24) != 7)
    {
      return; // only the user plane of the UEs (7.0.0.0/8)
    }
  uint32_t sport = 0, dport = 0;
  if (h.GetProtocol () == 17 && p->GetSize () >= 8)
    {
      UdpHeader u;
      p->PeekHeader (u);
      sport = u.GetSourcePort ();
      dport = u.GetDestinationPort ();
    }
  uint32_t sec = (uint32_t) Simulator::Now ().GetSeconds ();
  auto &e = g_flows[std::make_tuple (sec, src, dst, (uint32_t) h.GetProtocol (), sport, dport)];
  e.first += p->GetSize () + h.GetSerializedSize ();
  e.second += 1;
}

static void
WriteFlows (std::string fn)
{
  std::ofstream f (fn.c_str (), std::ios_base::out | std::ios_base::trunc);
  f << "t_s,src_ip,dst_ip,proto,src_port,dst_port,bytes,packets" << std::endl;
  for (auto &kv : g_flows)
    {
      f << std::get<0> (kv.first) << "," << Ipv4Address (std::get<1> (kv.first)) << ","
        << Ipv4Address (std::get<2> (kv.first)) << "," << std::get<3> (kv.first) << ","
        << std::get<4> (kv.first) << "," << std::get<5> (kv.first) << "," << kv.second.first << ","
        << kv.second.second << std::endl;
    }
}

int
main (int argc, char *argv[])
{
  Config::SetDefault ("ns3::MmWaveUePhy::NoiseFigure", DoubleValue (9.0));
  Config::SetDefault ("ns3::ThreeGppChannelModel::Blockage", BooleanValue (true));
  maxXAxis = 1000;
  maxYAxis = 1000;

  // ---------------- anomaly parameters (command line) ----------------
  bool anomalyOn = true;          // false = attack-free control run (same seed, same draws)
  uint32_t nAttackers = 2;        // UEs that receive the flood
  double attackRateMbps = 20.0;   // DL flood rate per attacked UE
  double attackStart = 10.0;      // s; the first seconds are attack-free in every run
  bool jammerOn = false;
  double jammerX = 710.0, jammerY = 510.0, jammerZ = 1.5, jammerPowerDbm = 50.0;
  std::string attackDir = "dl";   // "dl": flood towards the UE; "ul": flood from the UE
  uint32_t pktSize = 1000;        // bytes, all applications
  CommandLine cmd;
  cmd.AddValue ("anomalyOn", "Start the flood (false = control run)", anomalyOn);
  cmd.AddValue ("nAttackers", "Number of anomalous UEs", nAttackers);
  cmd.AddValue ("attackRateMbps", "Flood rate per anomalous UE [Mb/s]", attackRateMbps);
  cmd.AddValue ("attackStart", "Flood start time [s]", attackStart);
  cmd.AddValue ("attackDir", "dl (towards the UE) or ul (from the UE)", attackDir);
  cmd.AddValue ("jammerOn", "Enable the downlink jammer", jammerOn);
  cmd.AddValue ("jammerX", "Jammer x [m]", jammerX);
  cmd.AddValue ("jammerY", "Jammer y [m]", jammerY);
  cmd.AddValue ("jammerPowerDbm", "Jammer EIRP [dBm]", jammerPowerDbm);
  cmd.Parse (argc, argv); // --RngRun=<n> for independent runs

  bool harqEnabled = true;
  UintegerValue uintegerValue;
  BooleanValue booleanValue;
  StringValue stringValue;
  DoubleValue doubleValue;

  GlobalValue::GetValueByName ("hoSinrDifference", doubleValue);
  double hoSinrDifference = doubleValue.Get ();
  GlobalValue::GetValueByName ("bufferSize", uintegerValue);
  uint32_t bufferSize = uintegerValue.Get ();
  GlobalValue::GetValueByName ("enableTraces", booleanValue);
  bool enableTraces = booleanValue.Get ();
  GlobalValue::GetValueByName ("outageThreshold", doubleValue);
  double outageThreshold = doubleValue.Get ();
  GlobalValue::GetValueByName ("e2TermIp", stringValue);
  std::string e2TermIp = stringValue.Get ();
  GlobalValue::GetValueByName ("enableE2FileLogging", booleanValue);
  bool enableE2FileLogging = booleanValue.Get ();
  GlobalValue::GetValueByName ("KPM_E2functionID", doubleValue);
  double kpmFuncId = doubleValue.Get ();
  GlobalValue::GetValueByName ("RC_E2functionID", doubleValue);
  double rcFuncId = doubleValue.Get ();
  GlobalValue::GetValueByName ("numberOfRaPreambles", uintegerValue);
  uint8_t numberOfRaPreambles = uintegerValue.Get ();
  GlobalValue::GetValueByName ("e2lteEnabled", booleanValue);
  bool e2lteEnabled = booleanValue.Get ();
  GlobalValue::GetValueByName ("e2nrEnabled", booleanValue);
  bool e2nrEnabled = booleanValue.Get ();
  GlobalValue::GetValueByName ("e2du", booleanValue);
  bool e2du = booleanValue.Get ();
  GlobalValue::GetValueByName ("e2cuUp", booleanValue);
  bool e2cuUp = booleanValue.Get ();
  GlobalValue::GetValueByName ("e2cuCp", booleanValue);
  bool e2cuCp = booleanValue.Get ();
  GlobalValue::GetValueByName ("reducedPmValues", booleanValue);
  bool reducedPmValues = booleanValue.Get ();
  GlobalValue::GetValueByName ("indicationPeriodicity", doubleValue);
  double indicationPeriodicity = doubleValue.Get ();
  GlobalValue::GetValueByName ("controlFileName", stringValue);
  std::string controlFilename = stringValue.Get ();

  Config::SetDefault ("ns3::LteEnbNetDevice::ControlFileName", StringValue (controlFilename));
  Config::SetDefault ("ns3::LteEnbNetDevice::E2Periodicity", DoubleValue (indicationPeriodicity));
  Config::SetDefault ("ns3::MmWaveEnbNetDevice::E2Periodicity", DoubleValue (indicationPeriodicity));
  Config::SetDefault ("ns3::MmWaveHelper::E2ModeLte", BooleanValue (e2lteEnabled));
  Config::SetDefault ("ns3::MmWaveHelper::E2ModeNr", BooleanValue (e2nrEnabled));
  Config::SetDefault ("ns3::MmWaveEnbNetDevice::EnableDuReport", BooleanValue (e2du));
  Config::SetDefault ("ns3::MmWaveEnbNetDevice::EnableCuUpReport", BooleanValue (e2cuUp));
  Config::SetDefault ("ns3::LteEnbNetDevice::EnableCuUpReport", BooleanValue (e2cuUp));
  Config::SetDefault ("ns3::MmWaveEnbNetDevice::EnableCuCpReport", BooleanValue (e2cuCp));
  Config::SetDefault ("ns3::LteEnbNetDevice::EnableCuCpReport", BooleanValue (e2cuCp));
  Config::SetDefault ("ns3::MmWaveEnbNetDevice::ReducedPmValues", BooleanValue (reducedPmValues));
  Config::SetDefault ("ns3::LteEnbNetDevice::ReducedPmValues", BooleanValue (reducedPmValues));
  Config::SetDefault ("ns3::LteEnbNetDevice::EnableE2FileLogging", BooleanValue (enableE2FileLogging));
  Config::SetDefault ("ns3::MmWaveEnbNetDevice::EnableE2FileLogging", BooleanValue (enableE2FileLogging));
  Config::SetDefault ("ns3::LteEnbNetDevice::KPM_E2functionID", DoubleValue (kpmFuncId));
  Config::SetDefault ("ns3::MmWaveEnbNetDevice::KPM_E2functionID", DoubleValue (kpmFuncId));
  Config::SetDefault ("ns3::LteEnbNetDevice::RC_E2functionID", DoubleValue (rcFuncId));
  Config::SetDefault ("ns3::MmWaveEnbMac::NumberOfRaPreambles", UintegerValue (numberOfRaPreambles));
  Config::SetDefault ("ns3::MmWaveHelper::HarqEnabled", BooleanValue (harqEnabled));
  Config::SetDefault ("ns3::MmWaveHelper::UseIdealRrc", BooleanValue (true));
  Config::SetDefault ("ns3::MmWaveHelper::E2TermIp", StringValue (e2TermIp));
  Config::SetDefault ("ns3::MmWaveFlexTtiMacScheduler::HarqEnabled", BooleanValue (harqEnabled));
  Config::SetDefault ("ns3::MmWavePhyMacCommon::NumHarqProcess", UintegerValue (100));
  Config::SetDefault ("ns3::PhasedArrayModel::AntennaElement",
                      PointerValue (CreateObject<IsotropicAntennaModel> ()));
  Config::SetDefault ("ns3::ThreeGppChannelModel::UpdatePeriod", TimeValue (MilliSeconds (100.0)));
  Config::SetDefault ("ns3::ThreeGppChannelConditionModel::UpdatePeriod", TimeValue (MilliSeconds (100)));
  Config::SetDefault ("ns3::LteRlcAm::ReportBufferStatusTimer", TimeValue (MilliSeconds (10.0)));
  Config::SetDefault ("ns3::LteRlcUmLowLat::ReportBufferStatusTimer", TimeValue (MilliSeconds (10.0)));
  Config::SetDefault ("ns3::LteRlcUm::MaxTxBufferSize", UintegerValue (bufferSize * 1024 * 1024));
  Config::SetDefault ("ns3::LteRlcUmLowLat::MaxTxBufferSize", UintegerValue (bufferSize * 1024 * 1024));
  Config::SetDefault ("ns3::LteRlcAm::MaxTxBufferSize", UintegerValue (bufferSize * 1024 * 1024));
  Config::SetDefault ("ns3::LteEnbRrc::OutageThreshold", DoubleValue (outageThreshold));
  Config::SetDefault ("ns3::LteEnbRrc::SecondaryCellHandoverMode", StringValue ("Threshold"));
  Config::SetDefault ("ns3::LteEnbRrc::HoSinrDifference", DoubleValue (hoSinrDifference));
  Config::SetDefault ("ns3::ThreeGppPropagationLossModel::Frequency", DoubleValue (3.5e9));
  Config::SetDefault ("ns3::ThreeGppPropagationLossModel::ShadowingEnabled", BooleanValue (true));
  Config::SetDefault ("ns3::MmWaveEnbPhy::TxPower", DoubleValue (44.0));
  Config::SetDefault ("ns3::MmWaveEnbPhy::DlSinrWithJammers", BooleanValue (jammerOn));

  GlobalValue::GetValueByName ("Bandwidth", doubleValue);
  double bandwidth = doubleValue.Get ();
  GlobalValue::GetValueByName ("CenterFrequency", doubleValue);
  double centerFrequency = doubleValue.Get ();
  GlobalValue::GetValueByName ("IntersideDistanceCells", doubleValue);
  double isd_cell = doubleValue.Get ();

  Config::SetDefault ("ns3::McUeNetDevice::AntennaNum", UintegerValue (1));
  Config::SetDefault ("ns3::MmWaveNetDevice::AntennaNum", UintegerValue (1));
  Config::SetDefault ("ns3::MmWavePhyMacCommon::Bandwidth", DoubleValue (bandwidth));
  Config::SetDefault ("ns3::MmWavePhyMacCommon::CenterFreq", DoubleValue (centerFrequency));
  Ptr<MmWaveHelper> mmwaveHelper = CreateObject<MmWaveHelper> ();
  mmwaveHelper->SetPathlossModelType ("ns3::ThreeGppUmiStreetCanyonPropagationLossModel");
  mmwaveHelper->SetChannelConditionModelType ("ns3::ThreeGppUmiStreetCanyonChannelConditionModel");
  Ptr<MmWavePointToPointEpcHelper> epcHelper = CreateObject<MmWavePointToPointEpcHelper> ();
  mmwaveHelper->SetEpcHelper (epcHelper);

  GlobalValue::GetValueByName ("N_MmWaveEnbNodes", uintegerValue);
  uint8_t nMmWaveEnbNodes = uintegerValue.Get ();
  uint8_t nLteEnbNodes = 1;
  GlobalValue::GetValueByName ("N_Ues", uintegerValue);
  uint32_t nUeNodes = uintegerValue.Get ();
  if (nAttackers > nUeNodes)
    {
      nAttackers = nUeNodes;
    }

  Ptr<Node> pgw = epcHelper->GetPgwNode ();
  NodeContainer remoteHostContainer;
  remoteHostContainer.Create (1);
  Ptr<Node> remoteHost = remoteHostContainer.Get (0);
  InternetStackHelper internet;
  internet.Install (remoteHostContainer);
  PointToPointHelper p2ph;
  p2ph.SetDeviceAttribute ("DataRate", DataRateValue (DataRate ("100Gb/s")));
  p2ph.SetDeviceAttribute ("Mtu", UintegerValue (2500));
  p2ph.SetChannelAttribute ("Delay", TimeValue (Seconds (0.010)));
  NetDeviceContainer internetDevices = p2ph.Install (pgw, remoteHost);
  Ipv4AddressHelper ipv4h;
  ipv4h.SetBase ("1.0.0.0", "255.0.0.0");
  Ipv4InterfaceContainer internetIpIfaces = ipv4h.Assign (internetDevices);
  Ipv4Address remoteHostAddr = internetIpIfaces.GetAddress (1);
  Ipv4StaticRoutingHelper ipv4RoutingHelper;
  Ptr<Ipv4StaticRouting> remoteHostStaticRouting =
      ipv4RoutingHelper.GetStaticRouting (remoteHost->GetObject<Ipv4> ());
  remoteHostStaticRouting->AddNetworkRouteTo (Ipv4Address ("7.0.0.0"), Ipv4Mask ("255.0.0.0"), 1);
  // external host outside the operator domain (2.0.0.2): source of the downlink floods and
  // target of the IoT botnet; the benign content server stays at remoteHost (1.0.0.2)
  NodeContainer extHostContainer;
  extHostContainer.Create (1);
  Ptr<Node> extHost = extHostContainer.Get (0);
  internet.Install (extHostContainer);
  NetDeviceContainer extDevices = p2ph.Install (pgw, extHost);
  ipv4h.SetBase ("2.0.0.0", "255.0.0.0");
  Ipv4InterfaceContainer extIfaces = ipv4h.Assign (extDevices);
  Ipv4Address extHostAddr = extIfaces.GetAddress (1);
  ipv4RoutingHelper.GetStaticRouting (extHost->GetObject<Ipv4> ())
      ->AddNetworkRouteTo (Ipv4Address ("7.0.0.0"), Ipv4Mask ("255.0.0.0"), 1);
  PacketSinkHelper extSink ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), 60000));
  extSink.Install (extHost).Start (Seconds (0));
  pgw->GetObject<Ipv4L3Protocol> ()->TraceConnectWithoutContext ("UnicastForward",
                                                                 MakeCallback (&FlowLogForward));

  NodeContainer ueNodes, mmWaveEnbNodes, lteEnbNodes, allEnbNodes;
  mmWaveEnbNodes.Create (nMmWaveEnbNodes);
  lteEnbNodes.Create (nLteEnbNodes);
  ueNodes.Create (nUeNodes);
  allEnbNodes.Add (lteEnbNodes);
  allEnbNodes.Add (mmWaveEnbNodes);
  NodeContainerManager::GetInstance ().SetMmWaveEnbNodes (mmWaveEnbNodes);

  Vector centerPosition = Vector (maxXAxis / 2, maxYAxis / 2, 10);
  Ptr<ListPositionAllocator> enbPositionAlloc = CreateObject<ListPositionAllocator> ();
  enbPositionAlloc->Add (centerPosition);
  enbPositionAlloc->Add (centerPosition);
  double nConstellation = nMmWaveEnbNodes - 1;
  for (int8_t i = 0; i < nConstellation; ++i)
    {
      double x = isd_cell * cos ((2 * M_PI * i) / (nConstellation));
      double y = isd_cell * sin ((2 * M_PI * i) / (nConstellation));
      enbPositionAlloc->Add (Vector (centerPosition.x + x, centerPosition.y + y, 10));
    }
  MobilityHelper enbmobility;
  enbmobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
  enbmobility.SetPositionAllocator (enbPositionAlloc);
  enbmobility.Install (allEnbNodes);

  MobilityHelper uemobility;
  Ptr<UniformDiscPositionAllocator> uePositionAlloc = CreateObject<UniformDiscPositionAllocator> ();
  uePositionAlloc->SetX (centerPosition.x);
  uePositionAlloc->SetY (centerPosition.y);
  uePositionAlloc->SetZ (1.5);
  uePositionAlloc->SetRho (450.0);
  Ptr<UniformRandomVariable> speed = CreateObject<UniformRandomVariable> ();
  speed->SetAttribute ("Min", DoubleValue (3.0));
  speed->SetAttribute ("Max", DoubleValue (7.0));
  uemobility.SetMobilityModel ("ns3::RandomWalk2dOutdoorMobilityModel", "Speed", PointerValue (speed),
                               "Bounds", RectangleValue (Rectangle (0, maxXAxis, 0, maxYAxis)));
  uemobility.SetPositionAllocator (uePositionAlloc);
  uemobility.Install (ueNodes);
  NodeContainer jammerNode;
  jammerNode.Create (1);
  Ptr<ListPositionAllocator> jAlloc = CreateObject<ListPositionAllocator> ();
  jAlloc->Add (Vector (jammerX, jammerY, jammerZ));
  MobilityHelper jMob;
  jMob.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
  jMob.SetPositionAllocator (jAlloc);
  jMob.Install (jammerNode);
  Ptr<ThreeGppUmiStreetCanyonChannelConditionModel> jCond = CreateObject<ThreeGppUmiStreetCanyonChannelConditionModel> ();
  jCond->SetAttribute ("UpdatePeriod", TimeValue (MilliSeconds (100)));
  Ptr<ThreeGppUmiStreetCanyonPropagationLossModel> jPl = CreateObject<ThreeGppUmiStreetCanyonPropagationLossModel> ();
  jPl->SetAttribute ("Frequency", DoubleValue (3.5e9));
  jPl->SetAttribute ("ShadowingEnabled", BooleanValue (true));
  jPl->SetChannelConditionModel (jCond);
  if (jammerOn)
    {
      MmWaveEnbPhy::AddJammer (jammerNode.Get (0)->GetObject<MobilityModel> (), jammerPowerDbm, jPl);
      NS_LOG_UNCOND ("Jammer ON at (" << jammerX << ", " << jammerY << ") EIRP " << jammerPowerDbm << " dBm");
    }
  {
    std::ofstream jf ("jammer.txt", std::ios_base::out | std::ios_base::trunc);
    jf << "x,y,z,power_dbm,jammer_on,rng_run" << std::endl;
    jf << jammerX << "," << jammerY << "," << jammerZ << "," << jammerPowerDbm << ","
       << (jammerOn ? 1 : 0) << "," << RngSeedManager::GetRun () << std::endl;
  }

  double minDistance = 10.0;
  for (uint32_t i = 0; i < ueNodes.GetN (); ++i)
    {
      Ptr<MobilityModel> ueMobility = ueNodes.Get (i)->GetObject<MobilityModel> ();
      bool tooClose;
      do
        {
          tooClose = false;
          for (uint32_t j = 0; j < allEnbNodes.GetN (); ++j)
            {
              if (ueMobility->GetDistanceFrom (allEnbNodes.Get (j)->GetObject<MobilityModel> ()) < minDistance)
                {
                  ueMobility->SetPosition (uePositionAlloc->GetNext ());
                  tooClose = true;
                  break;
                }
            }
        }
      while (tooClose);
    }

  NetDeviceContainer lteEnbDevs = mmwaveHelper->InstallLteEnbDevice (lteEnbNodes);
  NetDeviceContainer mmWaveEnbDevs = mmwaveHelper->InstallEnbDevice (mmWaveEnbNodes);
  NetDeviceContainer mcUeDevs = mmwaveHelper->InstallMcUeDevice (ueNodes);
  internet.Install (ueNodes);
  Ipv4InterfaceContainer ueIpIface = epcHelper->AssignUeIpv4Address (NetDeviceContainer (mcUeDevs));
  {
    // IMSI <-> UE IP binding, as recorded by the core network (PDU session / CDR log)
    std::ofstream ipf ("ue_ip.txt", std::ios_base::out | std::ios_base::trunc);
    ipf << "imsi,ue_ip" << std::endl;
    for (uint32_t u = 0; u < mcUeDevs.GetN (); ++u)
      {
        ipf << mcUeDevs.Get (u)->GetObject<McUeNetDevice> ()->GetImsi () << ","
            << ueIpIface.GetAddress (u) << std::endl;
      }
  }
  for (uint32_t u = 0; u < ueNodes.GetN (); ++u)
    {
      Ptr<Ipv4StaticRouting> ueStaticRouting =
          ipv4RoutingHelper.GetStaticRouting (ueNodes.Get (u)->GetObject<Ipv4> ());
      ueStaticRouting->SetDefaultRoute (epcHelper->GetUeDefaultGatewayAddress (), 1);
    }
  mmwaveHelper->AddX2Interface (lteEnbNodes, mmWaveEnbNodes);
  mmwaveHelper->AttachToClosestEnb (mcUeDevs, mmWaveEnbDevs, lteEnbDevs);

  GlobalValue::GetValueByName ("simTime", doubleValue);
  double simTime = doubleValue.Get ();

  // ---------------- traffic: random draws are identical in attack and control runs ----------------
  Ptr<UniformRandomVariable> draw = CreateObject<UniformRandomVariable> ();
  draw->SetStream (1000); // fixed stream; the values still change with --RngRun

  // benign profile per UE: light 0.1-0.5, medium 0.5-2, heavy 2-6 Mb/s while ON
  std::vector<std::string> profile (nUeNodes);
  std::vector<double> benignMbps (nUeNodes);
  for (uint32_t u = 0; u < nUeNodes; ++u)
    {
      double c = draw->GetValue (0.0, 1.0);
      if (c < 0.5)
        {
          profile[u] = "light";
          benignMbps[u] = draw->GetValue (0.1, 0.5);
        }
      else if (c < 0.85)
        {
          profile[u] = "medium";
          benignMbps[u] = draw->GetValue (0.5, 2.0);
        }
      else
        {
          profile[u] = "heavy";
          benignMbps[u] = draw->GetValue (2.0, 6.0);
        }
    }
  // anomalous UEs: partial Fisher-Yates shuffle
  std::vector<uint32_t> idx (nUeNodes);
  for (uint32_t u = 0; u < nUeNodes; ++u)
    {
      idx[u] = u;
    }
  for (uint32_t k = 0; k < nAttackers; ++k)
    {
      uint32_t j = draw->GetInteger (k, nUeNodes - 1);
      std::swap (idx[k], idx[j]);
    }
  std::vector<bool> isAttacker (nUeNodes, false);
  for (uint32_t k = 0; k < nAttackers; ++k)
    {
      isAttacker[idx[k]] = true;
    }

  ApplicationContainer sinkApp, benignApps, attackApps;
  PacketSinkHelper sinkUl ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), 60000));
  sinkApp.Add (sinkUl.Install (remoteHost));
  int64_t stream = 2000;
  for (uint32_t u = 0; u < nUeNodes; ++u)
    {
      PacketSinkHelper dlSink ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), 1234));
      sinkApp.Add (dlSink.Install (ueNodes.Get (u)));
      PacketSinkHelper dlSinkAtk ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), 1235));
      sinkApp.Add (dlSinkAtk.Install (ueNodes.Get (u)));

      // benign ON/OFF downlink traffic
      OnOffHelper onoff ("ns3::UdpSocketFactory", InetSocketAddress (ueIpIface.GetAddress (u), 1234));
      onoff.SetConstantRate (DataRate ((uint64_t) (benignMbps[u] * 1e6)), pktSize);
      onoff.SetAttribute ("OnTime", StringValue ("ns3::ExponentialRandomVariable[Mean=3.0]"));
      onoff.SetAttribute ("OffTime", StringValue ("ns3::ExponentialRandomVariable[Mean=1.0]"));
      ApplicationContainer a = onoff.Install (remoteHost);
      stream += DynamicCast<OnOffApplication> (a.Get (0))->AssignStreams (stream);
      benignApps.Add (a);

      // flood application: created for every attacker in both runs, started only if anomalyOn
      if (isAttacker[u])
        {
          double interval = pktSize * 8.0 / (attackRateMbps * 1e6);
          ApplicationContainer f;
          if (attackDir == "ul")
            {
              UdpClientHelper ul (extHostAddr, 60000);
              ul.SetAttribute ("Interval", TimeValue (Seconds (interval)));
              ul.SetAttribute ("MaxPackets", UintegerValue (UINT32_MAX));
              ul.SetAttribute ("PacketSize", UintegerValue (pktSize));
              f = ul.Install (ueNodes.Get (u));
            }
          else
            {
              UdpClientHelper dl (ueIpIface.GetAddress (u), 1235);
              dl.SetAttribute ("Interval", TimeValue (Seconds (interval)));
              dl.SetAttribute ("MaxPackets", UintegerValue (UINT32_MAX));
              dl.SetAttribute ("PacketSize", UintegerValue (pktSize));
              f = dl.Install (extHost);
            }
          f.Start (anomalyOn ? Seconds (attackStart) : Seconds (simTime + 10.0));
          f.Stop (Seconds (simTime - 0.1));
          attackApps.Add (f);
        }
    }
  sinkApp.Start (Seconds (0));
  benignApps.Start (MilliSeconds (100));
  benignApps.Stop (Seconds (simTime - 0.1));

  // ---------------- ground truth ----------------
  {
    std::ofstream gt ("anomaly.txt", std::ios_base::out | std::ios_base::trunc);
    gt << "imsi,attacker,profile,benign_mbps,attack_mbps,attack_dir,attack_start_s,anomaly_on,rng_run"
       << std::endl;
    for (uint32_t u = 0; u < nUeNodes; ++u)
      {
        uint64_t imsi = mcUeDevs.Get (u)->GetObject<McUeNetDevice> ()->GetImsi ();
        gt << imsi << "," << (isAttacker[u] ? 1 : 0) << "," << profile[u] << "," << benignMbps[u] << ","
           << (isAttacker[u] ? attackRateMbps : 0.0) << "," << attackDir << "," << attackStart << ","
           << (anomalyOn ? 1 : 0) << "," << RngSeedManager::GetRun () << std::endl;
      }
  }
  for (uint32_t u = 0; u < nUeNodes; ++u)
    {
      if (isAttacker[u])
        {
          NS_LOG_UNCOND ("Anomalous UE IMSI "
                         << mcUeDevs.Get (u)->GetObject<McUeNetDevice> ()->GetImsi () << " flood "
                         << attackRateMbps << " Mb/s " << attackDir << " from t=" << attackStart
                         << " s" << (anomalyOn ? "" : " (control run: flood not started)"));
        }
    }

  // ---------------- position and gNB logs ----------------
  struct timeval time_now{};
  gettimeofday (&time_now, nullptr);
  uint64_t t_start = (time_now.tv_sec * 1000) + (time_now.tv_usec / 1000);
  std::string ue_pos_out = "ue_position.txt";
  ClearFile (ue_pos_out, t_start);
  ClearFile ("enbs.txt", t_start);
  ClearFile ("gnbs.txt", t_start);
  PrintGnuplottableUeListToFile ("ues.txt");
  int numPrints = simTime / 0.1;
  for (int i = 0; i < numPrints; i++)
    {
      Simulator::Schedule (Seconds (i * simTime / numPrints), &PrintGnuplottableEnbListToFile, t_start);
      for (uint32_t j = 0; j < ueNodes.GetN (); j++)
        {
          Simulator::Schedule (Seconds (i * simTime / numPrints), &PrintPosition, ueNodes.Get (j),
                               ue_pos_out, t_start);
        }
    }

  if (enableTraces)
    {
      mmwaveHelper->EnableTraces ();
    }
  else
    {
      mmwaveHelper->EnableMcTraces ();
    }
  Ptr<LteHelper> lteHelper = CreateObject<LteHelper> ();
  lteHelper->Initialize ();
  lteHelper->EnablePhyTraces ();
  lteHelper->EnableMacTraces ();

  NS_LOG_UNCOND ("Simulation time is " << simTime << " seconds");
  Simulator::Stop (Seconds (simTime));
  Simulator::Run ();
  WriteFlows ("it_flows.txt");
  MmWaveEnbPhy::ClearJammers ();
  Simulator::Destroy ();
  return 0;
}
