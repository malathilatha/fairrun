# Put the FairRun demo on AWS (EC2 + Docker, mock only)

Why EC2: Streamlit needs WebSockets, and AWS App Runner does not support them.
The public demo runs the MOCK world only. **Never put Airwallex or Anthropic keys on this server.**

## 1. Launch the instance (AWS console, region near you, e.g. me-central-1 or eu-west-1)
- EC2 -> Launch instance. Name: `fairrun-demo`
- Image: **Amazon Linux 2023**
- Type: **t3.small** (2 GB RAM; the proof step needs a little CPU)
- Key pair: create one and keep the .pem file private (needed only for SSH). Or use "EC2 Instance Connect" in the browser and skip it.
- Network -> Security group: allow **HTTP (80)** from Anywhere. Allow **SSH (22)** from **My IP** only.
- Storage: 16 GB is plenty. Launch.

## 2. Get the code onto it
Easiest: connect in the browser (EC2 -> Instance -> Connect -> EC2 Instance Connect), then:

    sudo dnf install -y git
    git clone <your repo URL> fairrun && cd fairrun     # repo must be reachable (public, or use a token)
    bash deploy/ec2_setup.sh

Private repo and no token? On your PC zip the fairrun folder (without employers_sandbox*.json), upload it
with `scp`, unzip, then run `bash deploy/ec2_setup.sh`.

## 3. Open it
The script prints `http://<public-ip>`. Open it, click situations 1-7, then the cheat tab.
Put that link in the README and the submission form.

## 4. Safety and cost
- Budget alert: Billing -> Budgets -> 5 USD.
- The public IP changes if you stop/start the instance. For a fixed address, attach an Elastic IP (free while attached to a running instance).
- After Demo Day: EC2 -> Instance state -> **Terminate**.
- Update the demo later: `cd fairrun && git pull && bash deploy/ec2_setup.sh`.

## 5. Check it works (from the instance)
    sudo docker ps                      # fairrun-demo should say "healthy"
    sudo docker logs fairrun | tail
