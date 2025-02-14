from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
import numpy as np
from datetime import datetime
from threading import Event
import logging
import pandas as pd
import os
from typing import List, Dict, Optional
from statistics import mean, stdev, variance
import smtplib
from email.mime.text import MIMEText
import re
import requests

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global variables
# Keep track of attack counts per IP
attack_counts = {}
flow_data = []
captured_packets = []
stop_capture_flag = Event()
FLOW_TIMEOUT = 120  
ACTIVITY_TIMEOUT = 1.0  
CSV_EXPORT_INTERVAL = 100000
FLOW_PACKET_THRESHOLD = 10
CSV_FILENAME = "network_flows.csv"

def calculate_packet_length_stats(packets: List) -> Dict:
    """Calculate packet length statistics."""
    try:
        lengths = [len(pkt) for pkt in packets if pkt.haslayer(IP)]
        if not lengths:
            return {'min': 0, 'max': 0, 'mean': 0, 'std': 0, 'total': 0, 'var': 0}
        return {
            'min': min(lengths),
            'max': max(lengths),
            'mean': mean(lengths),
            'std': stdev(lengths) if len(lengths) > 1 else 0,
            'var': variance(lengths) if len(lengths) > 1 else 0,
            'total': sum(lengths)
        }
    except Exception as e:
        logger.error(f"Error calculating packet length stats: {e}")
        return {'min': 0, 'max': 0, 'mean': 0, 'std': 0, 'var': 0, 'total': 0}

def calculate_iat_stats(times: List[float]) -> Dict:
    """Calculate Inter-Arrival Time statistics."""
    try:
        if len(times) < 2:
            return {'min': 0, 'max': 0, 'mean': 0, 'std': 0, 'total': 0}
        iats = np.diff(times)
        return {
            'min': float(np.min(iats)),
            'max': float(np.max(iats)),
            'mean': float(np.mean(iats)),
            'std': float(np.std(iats)),
            'total': float(np.sum(iats))
        }
    except Exception as e:
        logger.error(f"Error calculating IAT stats: {e}")
        return {'min': 0, 'max': 0, 'mean': 0, 'std': 0, 'total': 0}

def extract_protocol_flags(packet) -> Dict:
    """Extract protocol flags."""
    flags = {'FIN': 0, 'SYN': 0, 'RST': 0, 'PSH': 0, 'ACK': 0, 'URG': 0, 'ECE': 0, 'CWE': 0}
    try:
        if TCP in packet:
            tcp_flags = int(packet[TCP].flags)  # Convert FlagValue to int
            flags.update({
                'FIN': 1 if tcp_flags & 0x01 else 0,
                'SYN': 1 if tcp_flags & 0x02 else 0,
                'RST': 1 if tcp_flags & 0x04 else 0,
                'PSH': 1 if tcp_flags & 0x08 else 0,
                'ACK': 1 if tcp_flags & 0x10 else 0,
                'URG': 1 if tcp_flags & 0x20 else 0,
                'ECE': 1 if tcp_flags & 0x40 else 0,
                'CWE': 1 if tcp_flags & 0x80 else 0,
            })
    except Exception as e:
        logger.error(f"Error extracting protocol flags: {e}")
    return flags


def calculate_time_based_features(packet_times: List[float]) -> tuple:
    """Calculate active and idle times."""
    try:
        if len(packet_times) < 2:
            return (0, 0, 0, 0), (0, 0, 0, 0)

        active_times = []
        idle_times = []
        current_active_start = packet_times[0]
        last_time = packet_times[0]

        for time in packet_times[1:]:
            gap = time - last_time
            if gap > ACTIVITY_TIMEOUT:
                active_time = last_time - current_active_start
                if active_time > 0:
                    active_times.append(active_time)
                idle_times.append(gap)
                current_active_start = time
            last_time = time

        final_active = last_time - current_active_start
        if final_active > 0:
            active_times.append(final_active)

        # Calculate stats
        active_stats = (
            mean(active_times) if active_times else 0,
            stdev(active_times) if len(active_times) > 1 else 0,
            max(active_times) if active_times else 0,
            min(active_times) if active_times else 0
        )
        idle_stats = (
            mean(idle_times) if idle_times else 0,
            stdev(idle_times) if len(idle_times) > 1 else 0,
            max(idle_times) if idle_times else 0,
            min(idle_times) if idle_times else 0
        )
        return active_stats, idle_stats
    except Exception as e:
        logger.error(f"Error calculating active/idle times: {e}")
        return (0, 0, 0, 0), (0, 0, 0, 0)
    
def is_private_ip(ip):
    """Check if an IP address is private/local"""
    private_ranges = [
        re.compile(r'^10\.'),           # 10.0.0.0 to 10.255.255.255
        re.compile(r'^172\.(1[6-9]|2[0-9]|3[0-1])\.'),  # 172.16.0.0 to 172.31.255.255
        re.compile(r'^192\.168\.'),     # 192.168.0.0 to 192.168.255.255
        re.compile(r'^127\.'),          # Loopback addresses
        re.compile(r'^169\.254\.')      # Link-local addresses
    ]
    return any(pattern.match(ip) for pattern in private_ranges)



def get_country_from_ip(ip):
  """Get country and city for an IP using IP-API"""
  if is_private_ip(ip):
    return "Local Network"
  try:
    response = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
    if response.status_code == 200:
      data = response.json()
      country = data.get("countryCode", "Unknown")
      city = data.get("city", "Unknown")
      return f"{country}, {city}"  # Return country and city combined
    else:
      print(f"Error: {response.status_code}")
  except Exception as e:
    print(f"Geolocation error for {ip}: {e}")
  return "Unknown"

def extract_flow_features(packets: List) -> Optional[Dict]:
    """Extract flow-level features """
    try:
        if not packets:
            return None
        valid_packets = [pkt for pkt in packets if IP in pkt]
        if not valid_packets:
            return None

        src_ip = valid_packets[0][IP].src
        dst_ip = valid_packets[0][IP].dst
        
        # Add port and protocol extraction
        if TCP in valid_packets[0]:
            src_port = valid_packets[0][TCP].sport
            dst_port = valid_packets[0][TCP].dport
            protocol = 'TCP'
        elif UDP in valid_packets[0]:
            src_port = valid_packets[0][UDP].sport
            dst_port = valid_packets[0][UDP].dport
            protocol = 'UDP'
        else:
            src_port = dst_port = 0
            protocol = 'Unknown'
        
        flow_start_time = valid_packets[0].time
        flow_end_time = valid_packets[-1].time
        flow_duration = max(flow_end_time - flow_start_time, 1e-6)

        fwd_pkts = [pkt for pkt in valid_packets if pkt[IP].src == src_ip]
        bwd_pkts = [pkt for pkt in valid_packets if pkt[IP].src == dst_ip]

        fwd_stats = calculate_packet_length_stats(fwd_pkts)
        bwd_stats = calculate_packet_length_stats(bwd_pkts)

        # Calculate overall packet length stats
        all_pkt_stats = calculate_packet_length_stats(valid_packets)

        fwd_iat_stats = calculate_iat_stats([pkt.time for pkt in fwd_pkts])
        bwd_iat_stats = calculate_iat_stats([pkt.time for pkt in bwd_pkts])
        flow_iat_stats = calculate_iat_stats([pkt.time for pkt in valid_packets])

        # Active/Idle Times
        all_times = [pkt.time for pkt in valid_packets]
        active_stats, idle_stats = calculate_time_based_features(all_times)

        # Subflow Metrics
        subflow_fwd_pkts = len(fwd_pkts)
        subflow_bwd_pkts = len(bwd_pkts)
        subflow_fwd_bytes = fwd_stats['total']
        subflow_bwd_bytes = bwd_stats['total']

        # Initial Window Sizes
        init_fwd_win_bytes = fwd_pkts[0][TCP].window if fwd_pkts and TCP in fwd_pkts[0] else 0
        init_bwd_win_bytes = bwd_pkts[0][TCP].window if bwd_pkts and TCP in bwd_pkts[0] else 0

        # Packet Rates
        fwd_pkt_rate = len(fwd_pkts) / flow_duration
        bwd_pkt_rate = len(bwd_pkts) / flow_duration
        down_up_ratio = bwd_stats['total'] / max(fwd_stats['total'], 1e-6)

        # Detailed Flag Counts with PSH and URG Flags
        def count_direction_flags(packets, flag_type):
            return sum(1 for pkt in packets if TCP in pkt and pkt[TCP].flags & flag_type)

        flag_counts = {
            'FIN': 0, 'SYN': 0, 'RST': 0, 'PSH': 0, 'ACK': 0, 
            'URG': 0, 'CWE': 0, 'ECE': 0
        }
        for pkt in valid_packets:
            if TCP in pkt:
                flags = extract_protocol_flags(pkt)
                for flag, value in flags.items():
                    flag_counts[flag] += value

        # Specific Flag Counts for Directional Flags
        fwd_psh_flags = count_direction_flags(fwd_pkts, 0x08)
        bwd_psh_flags = count_direction_flags(bwd_pkts, 0x08)
        fwd_urg_flags = count_direction_flags(fwd_pkts, 0x20)
        bwd_urg_flags = count_direction_flags(bwd_pkts, 0x20)

        # Header Length Calculation
        fwd_header_len = sum(len(pkt[TCP].payload) if TCP in pkt else 0 for pkt in fwd_pkts)
        bwd_header_len = sum(len(pkt[TCP].payload) if TCP in pkt else 0 for pkt in bwd_pkts)

        # Block Rate and Bytes/Block Calculations (simplified)
        def calculate_block_metrics(packets, total_bytes):
            if not packets:
                return 0, 0
            block_count = len(packets)
            avg_bytes_per_block = total_bytes / block_count if block_count > 0 else 0
            return avg_bytes_per_block, block_count / flow_duration

        fwd_byts_b_avg, fwd_blk_rate_avg = calculate_block_metrics(fwd_pkts, fwd_stats['total'])
        bwd_byts_b_avg, bwd_blk_rate_avg = calculate_block_metrics(bwd_pkts, bwd_stats['total'])

        # Additional Derived Features
        fwd_seg_size_avg = fwd_stats['mean'] if fwd_pkts else 0
        bwd_seg_size_avg = bwd_stats['mean'] if bwd_pkts else 0
        
        # Forward Active Data Packets
        fwd_act_data_pkts = len([pkt for pkt in fwd_pkts if len(pkt[TCP].payload) > 0]) if fwd_pkts and TCP in fwd_pkts[0] else 0
        
        # Forward Segment Size Min (minimum packet length in forward direction)
        fwd_seg_size_min = min([len(pkt) for pkt in fwd_pkts]) if fwd_pkts else 0

        features = {
            # Existing features
            'Timestamp': datetime.fromtimestamp(flow_start_time).strftime('%Y-%m-%d %H:%M:%S'),
            'Src Port': src_port,
            'Dst Port': dst_port,
            'Src Country': get_country_from_ip(src_ip),
            'Dst Country': get_country_from_ip(dst_ip),
            'Protocol': protocol,
            'Src IP': src_ip,
            'Dst IP': dst_ip,
            
            # Flow Metrics
            'Flow Duration': flow_duration,
            'Flow Byts/s': (fwd_stats['total'] + bwd_stats['total']) / flow_duration,
            'Flow Pkts/s': len(valid_packets) / flow_duration,
            
            # Packet Counts and Lengths
            'Tot Fwd Pkts': len(fwd_pkts),
            'Tot Bwd Pkts': len(bwd_pkts),
            'TotLen Fwd Pkts': fwd_stats['total'],
            'TotLen Bwd Pkts': bwd_stats['total'],
            
            # Packet Length Statistics
            'Fwd Pkt Len Max': fwd_stats['max'],
            'Fwd Pkt Len Min': fwd_stats['min'],
            'Fwd Pkt Len Mean': fwd_stats['mean'],
            'Fwd Pkt Len Std': fwd_stats['std'],
            'Bwd Pkt Len Max': bwd_stats['max'],
            'Bwd Pkt Len Min': bwd_stats['min'],
            'Bwd Pkt Len Mean': bwd_stats['mean'],
            'Bwd Pkt Len Std': bwd_stats['std'],
            
            # Overall Packet Length Statistics
            'Pkt Len Min': all_pkt_stats['min'],
            'Pkt Len Max': all_pkt_stats['max'],
            'Pkt Len Mean': all_pkt_stats['mean'],
            'Pkt Len Std': all_pkt_stats['std'],
            'Pkt Len Var': all_pkt_stats['var'],
            'Pkt Size Avg': all_pkt_stats['mean'],
            
            # IAT Statistics
            'Flow IAT Mean': flow_iat_stats['mean'],
            'Flow IAT Std': flow_iat_stats['std'],
            'Flow IAT Max': flow_iat_stats['max'],
            'Flow IAT Min': flow_iat_stats['min'],
            'Fwd IAT Tot': fwd_iat_stats['total'],
            'Fwd IAT Mean': fwd_iat_stats['mean'],
            'Fwd IAT Std': fwd_iat_stats['std'],
            'Fwd IAT Max': fwd_iat_stats['max'],
            'Fwd IAT Min': fwd_iat_stats['min'],
            'Bwd IAT Tot': bwd_iat_stats['total'],
            'Bwd IAT Mean': bwd_iat_stats['mean'],
            'Bwd IAT Std': bwd_iat_stats['std'],
            'Bwd IAT Max': bwd_iat_stats['max'],
            'Bwd IAT Min': bwd_iat_stats['min'],
            
            # Directional Flags
            'Fwd PSH Flags': fwd_psh_flags,
            'Bwd PSH Flags': bwd_psh_flags,
            'Fwd URG Flags': fwd_urg_flags,
            'Bwd URG Flags': bwd_urg_flags,
            
            # Flag Counts
            'FIN Flag Cnt': flag_counts['FIN'],
            'SYN Flag Cnt': flag_counts['SYN'],
            'RST Flag Cnt': flag_counts['RST'],
            'PSH Flag Cnt': flag_counts['PSH'],
            'ACK Flag Cnt': flag_counts['ACK'],
            'URG Flag Cnt': flag_counts['URG'],
            'CWE Flag Count': flag_counts['CWE'],
            'ECE Flag Cnt': flag_counts['ECE'],
            
            # Packet Rates and Ratios
            'Fwd Pkts/s': fwd_pkt_rate,
            'Bwd Pkts/s': bwd_pkt_rate,
            'Down/Up Ratio': down_up_ratio,
            
            # Block and Bytes Metrics
            'Fwd Byts/b Avg': fwd_byts_b_avg,
            'Fwd Pkts/b Avg': fwd_blk_rate_avg,
            'Fwd Blk Rate Avg': fwd_blk_rate_avg,
            'Bwd Byts/b Avg': bwd_byts_b_avg,
            'Bwd Pkts/b Avg': bwd_blk_rate_avg,
            'Bwd Blk Rate Avg': bwd_blk_rate_avg,
            
            # Segment Size
            'Fwd Seg Size Avg': fwd_seg_size_avg,
            'Bwd Seg Size Avg': bwd_seg_size_avg,
            'Fwd Seg Size Min': fwd_seg_size_min,
            
            # Header Lengths
            'Fwd Header Len': fwd_header_len,
            'Bwd Header Len': bwd_header_len,
            
            # Subflow Metrics
            'Subflow Fwd Pkts': subflow_fwd_pkts,
            'Subflow Fwd Byts': subflow_fwd_bytes,
            'Subflow Bwd Pkts': subflow_bwd_pkts,
            'Subflow Bwd Byts': subflow_bwd_bytes,
            
            # Initial Window Bytes
            'Init Fwd Win Byts': init_fwd_win_bytes,
            'Init Bwd Win Byts': init_bwd_win_bytes,
            
            # Active and Forward Data Packets
            'Fwd Act Data Pkts': fwd_act_data_pkts,
            
            # Active and Idle Times
            'Active Mean': active_stats[0],
            'Active Std': active_stats[1],
            'Active Max': active_stats[2],
            'Active Min': active_stats[3],
            'Idle Mean': idle_stats[0],
            'Idle Std': idle_stats[1],
            'Idle Max': idle_stats[2],
            'Idle Min': idle_stats[3],
        }
        return features
    except Exception as e:
        logger.error(f"Error in extract_flow_features: {e}")
        return None

def save_to_csv():
    """Save the flow data to CSV file with proper error handling"""
    try:
        global flow_data
        if flow_data:
            df = pd.DataFrame(flow_data)
            mode = 'w' if not os.path.exists(CSV_FILENAME) else 'a'
            header = not os.path.exists(CSV_FILENAME)
            
            df.to_csv(CSV_FILENAME, mode=mode, header=header, index=False)
            logger.info(f"{'Created new' if header else 'Appended to'} CSV file: {CSV_FILENAME} ({len(flow_data)} flows)")
            
            flow_data = []
    except Exception as e:
        logger.error(f"Error saving to CSV: {e}")

def process_packets(predict_model):
    """Process captured packets and generate predictions"""
    global captured_packets, flow_data
    try:
        if captured_packets:
            features = extract_flow_features(captured_packets)
            if features:
                prediction = predict_model(features)
                features['Prediction'] = prediction
                flow_data.append(features)
                logger.info(f"[{features['Timestamp']}] Flow {features['Src IP']} -> {features['Dst IP']}: {prediction}")

                # Update attack count for the source-destination pair
                src_ip = features['Src IP']
                dst_ip = features['Dst IP']
                if prediction == 'Attack':
                    attack_key = (src_ip, dst_ip)  # Track pair (src_ip, dst_ip)
                    attack_counts[attack_key] = attack_counts.get(attack_key, 0) + 1
                    if attack_counts[attack_key] >= 10:  # Threshold for same pair
                        send_admin_alert(src_ip, dst_ip)

                if len(flow_data) >= CSV_EXPORT_INTERVAL:
                    save_to_csv()
    except Exception as e:
        logger.error(f"Error in process_packets: {e}")
    finally:
        captured_packets = []

def send_admin_alert(src_ip, dst_ip):
    """Send an alert email to the admin"""
    try:
        admin_email = 'reciver email'
        subject = f"NIDS Alert: Possible Attack from {src_ip} to {dst_ip}"
        body = f"""
        The NIDS has detected more than 10 attacks from the following network flow:
        
        Source IP: {src_ip}
        Destination IP: {dst_ip}
        
        Please investigate this suspicious network activity.
        """

        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = 'sender email'
        msg['To'] = admin_email

        # Use Gmail SMTP server
        with smtplib.SMTP('smtp.gmail.com', 587) as smtp:
            smtp.starttls()
            smtp.login('sender email', 'app password')
            smtp.send_message(msg)
        
        logger.info(f"Alert email sent to {admin_email} for IP {src_ip} -> {dst_ip}")
    except Exception as e:
        logger.error(f"Error sending admin alert: {e}")

def packet_filter(packet):
    """Filter packets based on protocols"""
    try:
        return IP in packet and (TCP in packet or UDP in packet)
    except:
        return False

def add_packet(predict_model):
    def packet_handler(packet):
        global captured_packets
        try:
            if not packet_filter(packet):
                return
            
            if captured_packets:
                # Check if the current packet matches the existing flow
                current_flow_src = captured_packets[0][IP].src
                current_flow_dst = captured_packets[0][IP].dst
                
                # Strict 5-tuple match conditions
                same_flow = (
                    packet[IP].src == current_flow_src and
                    packet[IP].dst == current_flow_dst and
                    # Check source port
                    ((TCP in packet and TCP in captured_packets[0] and 
                      packet[TCP].sport == captured_packets[0][TCP].sport) or 
                     (UDP in packet and UDP in captured_packets[0] and 
                      packet[UDP].sport == captured_packets[0][UDP].sport)) and
                    # Check destination port
                    ((TCP in packet and TCP in captured_packets[0] and 
                      packet[TCP].dport == captured_packets[0][TCP].dport) or 
                     (UDP in packet and UDP in captured_packets[0] and 
                      packet[UDP].dport == captured_packets[0][UDP].dport)) and
                    # Check protocol
                    type(packet.payload) == type(captured_packets[0].payload) and
                    # Check time threshold
                    packet.time - captured_packets[0].time <= FLOW_TIMEOUT
                )
                
                if not same_flow:
                    process_packets(predict_model)
                    captured_packets = [packet]
                else:
                    captured_packets.append(packet)
                    
                    # Strictly process when exactly 10 packets are captured
                    if len(captured_packets) == FLOW_PACKET_THRESHOLD:
                        process_packets(predict_model)
            else:
                captured_packets = [packet]
        except Exception as e:
            logger.error(f"Error in packet_handler: {e}")
    
    return packet_handler
    

def capture_packets(interface: str, predict_model):
    """Start packet capture on specified interface"""
    global stop_capture_flag
    stop_capture_flag.clear()
    try:
        logger.info(f"Starting packet capture on interface: {interface}")
        sniff(
            iface=interface,
            prn=add_packet(predict_model),
            store=0,
            stop_filter=lambda x: stop_capture_flag.is_set()
        )
        
        # Process remaining flows
        if captured_packets:
            process_packets(predict_model)
        if flow_data:
            save_to_csv()
    except Exception as e:
        logger.error(f"Error in capture: {e}")

def stop_capture():
    """Stop the packet capture"""
    stop_capture_flag.set()