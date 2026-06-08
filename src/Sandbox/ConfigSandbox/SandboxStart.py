import boto3
import time

# clasa aflata pe server-ul intermediar ce se ocupa de instantele EC2

class SandboxManager:
    def __init__(self):
        
        self.imageID = "ami-06a0e912497b0718f"
        self.region = "eu-central-1"
        self.type = "m7i-flex.large"
        self.securityGroup = "sg-0804e3b7e059954e6"
        self.subnet = "subnet-06a2636f90b95f5c2"
        self.roleIAM = "Sandbox-S3-access"
        self.keyName = "CheieSandbox"

        self.ec2 = boto3.client("ec2",region_name = self.region)
        self.ssm = boto3.client('ssm', region_name=self.region)
    
    def start(self):
        try:
            response = self.ec2.run_instances(
                ImageId = self.imageID,
                InstanceType = self.type,
                MinCount = 1,
                MaxCount = 1,
                KeyName = self.keyName,
                SubnetId =self.subnet,
                SecurityGroupIds =[self.securityGroup],
                IamInstanceProfile = {"Name": self.roleIAM},
                TagSpecifications = [
                    {
                        "ResourceType": "instance",
                        "Tags": [{"Key": "Name", "Value": "Sandbox-SSM-Managed"}]
                    }
                ]
            )

            instanceId = response["Instances"][0]["InstanceId"]

            waiter = self.ec2.get_waiter('instance_running')
            waiter.wait(InstanceIds=[instanceId])

            status = self.wait(instanceId)

            return instanceId, status


        except Exception as e:
            print(f"Eroare la deschidere Sandbox :{e}")
            return None, False
    
    def delete(self, instanceId):
        try:
            self.ec2.terminate_instances(InstanceIds=[instanceId])
        except Exception as e:
            print(f"Eroare la terminarea instantei: {e}")

    

    def wait(self, instanceId, maxCnt = 40):
        for i in range(maxCnt):
            try:
                response = self.ssm.describe_instance_information(
                    InstanceInformationFilterList = [{'key': 'InstanceIds', 'valueSet': [instanceId]}]
                )

                info = response.get("InstanceInformationList", [])
                if info != []:
                    status = info[0].get("PingStatus")

                    if status == "Online":
                        return True
            except Exception as e:
                pass
            
            time.sleep(5)
        
        return False
    



def funcSandboxStart(sandboxManager: SandboxManager):
    

    startTime = time.time()

    instanceId, isReady = sandboxManager.start()

    endTime = time.time()

    durata = round(endTime - startTime, 2)

    if not instanceId or not isReady:
        return False, "Error at starting sandbox"

    return instanceId, "Succes"


def funcDeleteInstance(sandboxManager: SandboxManager, instanceId):
    sandboxManager.delete(instanceId)
