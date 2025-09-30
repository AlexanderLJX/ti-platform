import pandas as pd
import glob

print('Loading ALL Mandiant files...')
mandiant_files = glob.glob('downloads/mandiant/*.csv')
m_dfs = []
for f in mandiant_files:
    m_dfs.append(pd.read_csv(f))
m_df = pd.concat(m_dfs, ignore_index=True)
print(f'Total Mandiant indicators: {len(m_df)}')

print('Loading ALL CrowdStrike files...')
crowdstrike_files = glob.glob('downloads/crowdstrike/*.csv')
c_dfs = []
for f in crowdstrike_files:
    c_dfs.append(pd.read_csv(f))
c_df = pd.concat(c_dfs, ignore_index=True)
print(f'Total CrowdStrike indicators: {len(c_df)}')

# Normalize and compare
m_indicators = set(m_df['Indicator Value'].dropna().astype(str).str.lower().str.strip())
c_indicators = set(c_df['indicator'].dropna().astype(str).str.lower().str.strip())

overlap = m_indicators.intersection(c_indicators)
print(f'\nTOTAL OVERLAPPING INDICATORS: {len(overlap)}')
print(f'Percentage: {len(overlap)/len(m_indicators)*100:.2f}% of Mandiant')
print(f'Percentage: {len(overlap)/len(c_indicators)*100:.2f}% of CrowdStrike')

print(f'\nSample overlaps (first 20):')
for i, ind in enumerate(list(overlap)[:20]):
    print(f'  {i+1}. {ind}')

# Check IP overlaps specifically
m_ips = set()
c_ips = set()

for val in m_df['Indicator Value'].dropna():
    val_str = str(val).strip()
    # Simple IP check
    if val_str.replace('.', '').isdigit() and val_str.count('.') == 3:
        m_ips.add(val_str)

for val in c_df['indicator'].dropna():
    val_str = str(val).strip()
    if val_str.replace('.', '').isdigit() and val_str.count('.') == 3:
        c_ips.add(val_str)

ip_overlap = m_ips.intersection(c_ips)
print(f'\nIP ADDRESS OVERLAPS: {len(ip_overlap)}')
if ip_overlap:
    print('Sample overlapping IPs:')
    for i, ip in enumerate(list(ip_overlap)[:10]):
        print(f'  {i+1}. {ip}')