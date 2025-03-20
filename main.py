import subprocess
import requests
import os
import time
# import shutil
# from git import Repo
import aiohttp
import asyncio
# import pandas as pd
from datetime import datetime
from database import Database
# import hashlib

class SonarqubeReport:
    def __init__(self, base_port=9000, cache_dir="tmp/sonar_cache/", context_extractor=None):
        self.container_name = f"sonarqube"
        self.network_name = "sonar_network"
        self.base_port = base_port
        self.sonar_url = f"http://172.17.0.1:9000"
        self.sonar_url_inside_docker = f"http://172.17.0.1:9000"
        self.login_info_sq = {
            'user': os.getenv('SONAR_USERNAME', 'admin'),
            'password': os.getenv('SONAR_PASSWORD', 'admin')
        }
        
        if context_extractor is not None:
            self.routine_name, self.db, self.current_step_name, self.mode = context_extractor
        self.headers = {}
        self.api_token = None
        self.default_repos_path = os.getcwd()
        self.cache_dir = os.path.join(self.default_repos_path, cache_dir)
        self.dir_to_scan = os.path.join(self.default_repos_path, 'scan_here')
        self.db_path = os.path.join(self.default_repos_path, 'output', 'main.db')
        
        self.sonarqube_on = False
        self.docker_reset()
        if not os.path.exists(self.cache_dir):
            os.makedirs(self.cache_dir, exist_ok=True)
        
        if not os.path.exists(self.dir_to_scan):
            os.makedirs(self.dir_to_scan, exist_ok=True)
            
        self.db = Database(self.db_path)
        self.create_table()
            
    def docker_reset(self):
        subprocess.run(["docker", "compose", "down", "--remove-orphans", "--volumes"], check=False)
        subprocess.run(["docker", "compose", "up", "sonarqube", "-d"], check=False)
        pass
    
    def create_table(self):
        create_data_snqb_table = f"""
            CREATE TABLE IF NOT EXISTS data_snqb (
                project_name TEXT,
                variable_name TEXT,
                value TEXT,
                PRIMARY KEY (project_name, variable_name)  
            );
            """
        self.db.execute_sql(create_data_snqb_table)
    
    async def run_analysis_instance(self, project_set):
        project_name, project_key, project_id = project_set
        await self._create_sonar_project(project_name, project_key, project_id)
        
        project_dir_path = os.path.join(self.dir_to_scan, project_name)
        
        await self._run_scanner(project_name, project_id, project_dir_path)
        metrics = await self._gather_metrics(project_id)
        await self.format_output_data(metrics, project_id, self.default_repos_path)
        
        await self._delete_project(project_name, project_key, project_id)
        return True
        
                
    async def run_analysis(self, project_set, limit=4):
        """
        Gather metrics for each project using the SonarQube Web API .
        """
        results = []
        # print('running run_analysis')
        semaphore = asyncio.Semaphore(limit)
        total_tasks = len(project_set)
        completed_tasks = 0
        
        async def limited_run(project_info):
            async with semaphore:
                return await self.run_analysis_instance(project_info)

        tasks = [asyncio.create_task(limited_run(project_info)) for project_info in project_set]

        for finished_task in asyncio.as_completed(tasks):
            result = await finished_task
            completed_tasks += 1
            
            print(f"Progress: {completed_tasks}/{total_tasks} tasks completed")

    
    async def _run_scanner(self, project_name, project_id, project_dir_path, retries=5):
        for attempt in range(retries):
            try:
                # chmod -R 777 /home/enio/projects/research/adrs/scanner_cache
            
                print(f"Running SonarScanner for project '{project_name}' at '{project_dir_path}'...")
                process = await asyncio.create_subprocess_exec(
                    'docker-compose', 'run',
                    '--rm',
                    '-v', f'{project_dir_path}:/usr/src/{project_name}',
                    'sonar-scanner-cli', 
                    '-Dsonar.projectKey=' + project_id,
                    '-Dsonar.projectName=' + project_name,
                    '-Dsonar.sources=' + project_name,
                    '-Dsonar.host.url=' + self.sonar_url_inside_docker,
                    '-Dsonar.login=' + self.api_token,
                    '-D', "sonar.exclusions=**/*.java",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process.communicate()
                
                if process.returncode == 0:
                    print(f'sonarscanner ran successfuly {stdout.decode()} {stderr.decode()}')
                    return
                else:
                    print(f"SonarScanner failed with return code {process.returncode}")
                    print(stderr.decode())
                    await asyncio.sleep(2)
                    raise Exception("SonarScanner failed")
            except Exception as e:
                print(f"Attempt {attempt + 1}/{retries} failed: {e}")
                await asyncio.sleep(2)
        raise Exception("SonarScanner analysis failed after multiple attempts.")

    async def _gather_metrics(self, project_id, max_retries=5000):
        metric_keys = [
            'bugs', 'new_bugs', 'vulnerabilities', 'new_vulnerabilities', 'code_smells', 'new_code_smells', 'high_impact_accepted_issues', 'new_blocker_violations', 'new_critical_violations', 'new_major_violations', 'new_minor_violations', 'new_info_violations', 'blocker_violations', 'critical_violations', 'major_violations', 'minor_violations', 'info_violations', "security_hotspots", "complexity", "cognitive_complexity", "coverage", "line_coverage", "branch_coverage", "ncloc", "lines","files", "functions", "statements", "comment_lines","comment_lines_density", 'software_quality_blocker_issues', 'software_quality_high_issues', 'software_quality_info_issues', 'software_quality_medium_issues', 'software_quality_low_issues', 'software_quality_maintainability_issues', 'software_quality_reliability_issues', 'software_quality_security_issues', 'new_software_quality_blocker_issues', 'new_software_quality_high_issues', 'new_software_quality_info_issues', 'new_software_quality_medium_issues', 'new_software_quality_low_issues', 'new_software_quality_maintainability_issues', 'new_software_quality_reliability_issues', 'new_software_quality_security_issues'
        ]
        
        url = f"{self.sonar_url}/api/measures/component"
        params = {
                "component": project_id,
                "metricKeys": ",".join(metric_keys)}
        
        retries = 0
        info = {}
        async with aiohttp.ClientSession(auth=aiohttp.BasicAuth('admin', 'admin')) as session:
            while retries < max_retries:
                try:
                    async with session.get(url, params=params) as response:
                        if response.status == 200:
                            data = await response.json()
                            measures = data.get("component", {}).get("measures", [])
                            if measures:
                                print(f'received')
                                info[project_id] = measures
                                return info
                            # else:
                            #     print(f"Metrics not yet available for project '{project_id}', retrying...")
                        elif response.status in [404, 503]:
                            # pass
                            print(f"The Server returned {response.status} for project '{project_id}', retrying...")
                            await asyncio.sleep(5)
                            retries += 1
                        else:
                            print(f"Failed to gather metrics for project '{project_id}'. Status Code: {response.status}")
                            response_text = await response.text()
                            # print(f"Response: {response_text}")
                            return response_text
                except aiohttp.ClientError as e:
                    print(f"Network error occurred: {e}")
                    
    async def format_output_data(self, metrics_info, project_id, output_dir):
        
        # os.makedirs(output_dir, exist_ok=True)
        metrics = []
        for metric_info in metrics_info.get(project_id, []):
            metric = {
                'project_name': project_id,
                'variable_name': metric_info.get("metric"), 
                'value': str(metric_info.get("value")), 
            }
            
            self.db.cache(metric, 'data_snqb')
            
        is_saved = self.db.save()  

    def _get_original_dir(self, project_name):
        project_dir_path = os.path.join(self.default_repos_path, project_name)
        dirs_in_repo = [os.path.join(project_dir_path, dir) for dir in os.listdir(project_dir_path) if (os.path.isdir(os.path.join(project_dir_path, dir))) and ('_hash_' not in dir and 'tmp' not in dir)]
        if len(dirs_in_repo) == 1:
            project_path = dirs_in_repo[0]
            return project_path
        else:
            raise Exception(f'More than one directory inside the project_dir_path {project_dir_path}, {dirs_in_repo}')
        
    
  




    # def _checkout_repo(self, repo_path, commit_hash):
    #     repo = Repo(repo_path)
    #     try:
    #         # Checkout to the specified commit
    #         repo.git.checkout(commit_hash, force=True)
    #         # print(f"Checked out to commit {commit_hash}")

    #         # Define directories to remove
    #         dirs_to_remove = [".git", ".github"]  # Add other non-essential directories here

    #         # Remove each directory if it exists
    #         for dir_name in dirs_to_remove:
    #             dir_path = os.path.join(repo_path, dir_name)
    #             if os.path.isdir(dir_path):
    #                 shutil.rmtree(dir_path)
    #                 # print(f"Removed directory: {dir_path}")

    #     except Exception as e:
    #         raise Exception(f"Failed to checkout to commit {commit_hash}: {e}")

    async def _create_sonar_project(self, project_name, project_key, project_id):
        url = f"{self.sonar_url}/api/projects/create"
        data = {
            "name": project_id,
            "project": project_id
        }
        async with aiohttp.ClientSession(auth=aiohttp.BasicAuth('admin', 'admin')) as session:
            async with session.post(url, data=data) as response:
                if response.status == 200:
                    print(f"Project '{data['name']}' created successfully.")
                    pass
                else:
                    response_text = await response.text()
                    print(f"Failed to create project '{data['name']}'. Status Code: {response.status}")
                    print(f"Response: {response_text}")
        
    async def _is_project_present(self, project_id, retries=20):
        url = f"{self.sonar_url}/api/projects/search"
        params = {"projects": project_id}
        retry = 0
        async with aiohttp.ClientSession(auth=aiohttp.BasicAuth('admin', 'admin')) as session:
            while retry < retries:
                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        project_data = await response.json()
                        if 'components' in project_data and len(project_data['components']) > 0:
                            return True
                        else:
                            return False
                    else:
                        retry += 1
                        await asyncio.sleep(2)
            raise Exception(f"Error checking project presence after {retries} retries.")
    
    async def _delete_project(self, project_name, project_key, project_id, retries=20):
        is_present_online = await self._is_project_present(project_id)
        if is_present_online:
            url = f"{self.sonar_url}/api/projects/delete"
            data = {
                "name": project_name,
                "project": project_id
            }
            retry = 0
            async with aiohttp.ClientSession(auth=aiohttp.BasicAuth('admin', 'admin')) as session:
                while retry < retries:
                    try:
                        async with session.post(url, data=data) as response:
                            if response.status == 200:
                                is_deleted = not await self._is_project_present(project_id)
                                if is_deleted:
                                    break
                                else:
                                    return False
                            else:
                                retry += 1
                                await asyncio.sleep(2)
                        if retry >= retries:
                            raise Exception(f"Error deleting project after {retries} retries.")
                    except aiohttp.ClientError as e:
                        print(f"Network error occurred: {e}")
                        retry += 1
                        await asyncio.sleep(2)
                    if retry >= retries:
                        raise Exception(f"Error deleting project after {retries} retries.")

        
    def run_and_is_on_sonarqube(self, max_retries=1800, delay=1):
        import subprocess
        import socket
        
        hostname = socket.gethostname()
        if self.sonarqube_on:
            return 
        
        time.sleep(10)
        url = f"{self.sonar_url}/api/system/status"
        retries = 0
        while retries < max_retries:
            try:
                response = requests.get(url)
                if response.status_code == 200:
                    try:
                        json_response = response.json()
                        status = json_response.get("status")
                        if status in ("UP"):
                            print(f"SonarQube is operational (status: {status}).")
                            self._login()
                            self._get_api_key()
                            self.sonarqube_on = True   
                            return True
                        else:
                            print(f"SonarQube is not fully operational (status: {status}), retrying...")
                    except ValueError:
                        print("Received non-JSON response, SonarQube is still starting up, retrying...")
                else:
                    print(f"Unexpected status code {response.status_code}, retrying...")
            except requests.ConnectionError as e:
                print(f"SonarQube server not reachable, retrying... {e}")
            time.sleep(delay)
            retries += 1
        raise Exception("SonarQube server did not become operational in time.")
    
    def _get_api_key(self):
        if self.api_token is not None:
            return
        url = f"{self.sonar_url}/api/user_tokens/generate"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        parameters = {
            "name": f'global_admin_token_{timestamp}',
            "type": 'GLOBAL_ANALYSIS_TOKEN'
        }
        self.headers={}
        try:
            response = requests.post(url, data=parameters, auth=('admin', 'admin'))
            if response.status_code == 200:
                # If authentication is successful, SonarQube returns 200
                json_response = response.json()
                self.api_token = json_response.get("token")
                self.headers = {
                    "Authorization": f"Bearer {self.api_token}",
                }
                # print(f"Token obtained")
            else:
                # If the login fails, SonarQube returns a different status code
                print(f"Token failed: {response.status_code}, token: {self.api_token}")
                print(f"Response: {response.text}")
                raise Exception
        except requests.RequestException as e:
            print(f"An error occurred while trying to login: {e}")
            raise Exception(f"An error occurred while trying to login: {e}")
        
    def _login(self):
        url = f"{self.sonar_url}/api/authentication/login"
        data = {"login": self.login_info_sq['user'], "password": self.login_info_sq['password']}
        try:
            response = requests.post(url, data=data)
            if response.status_code == 200:
                return
            else:
                print(f"Login failed. Status code: {response.status_code}")
                print(f"Response: {response.text}")
        except requests.RequestException as e:
            print(f"An error occurred while trying to login: {e}")
            
async def main():
    sonar_report = SonarqubeReport()
    try:
        dirs_to_scan = [dir_to_scan for dir_to_scan in os.listdir(sonar_report.dir_to_scan) if os.path.isdir(os.path.join(sonar_report.dir_to_scan, dir_to_scan))]
        
        project_keys = range(len(dirs_to_scan))
        project_names = [dir_to_scan for dir_to_scan in dirs_to_scan]
        project_ids = [f"{dir_to_scan}_-_{project_key}" for dir_to_scan, project_key in zip(dirs_to_scan, project_keys)]
        
        project_set = []
        
        for name, key, proj_id in zip(project_names, project_keys, project_ids):
            project_set.append((name, key, proj_id))  # Append a tuple
        
        print(f'{project_set}')
        sonar_report.run_and_is_on_sonarqube()
        await sonar_report.run_analysis(project_set)

    except Exception as e:
        print(f'process failed: {e}')
    sonar_report.docker_reset()
    
if __name__ == "__main__":
    asyncio.run(main())