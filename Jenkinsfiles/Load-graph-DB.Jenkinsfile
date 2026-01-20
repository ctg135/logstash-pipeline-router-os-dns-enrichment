pipeline {
    agent any

    stages {
        stage('Checkout SCM') {
            steps {
                checkout([
                    $class: 'GitSCM',
                    branches: [[name: '*/master']],
                    doGenerateSubmoduleConfigurations: false,
                    extensions: [],
                    userRemoteConfigs: [[
                        url: 'https://github.com/ctg135/logstash-pipeline-router-os-dns-enrichment.git'
                    ]]
                ])
            }
        }

        stage('Setup Python environment') {
            steps {
                dir('scripts') {
                    sh '''
                        python3 -m venv .venv
                        . .venv/bin/activate
                        pip install --upgrade pip
                        pip install -r requirements.txt
                    '''
                }
            }
        }

        stage('Run Script') {
            steps {
                dir('scripts') {
                    sh '''
                        . .venv/bin/activate
                        python3 main.py
                    '''
                }
            }
        }
    }
    
    post {
        cleanup {
            sh 'rm -rf scripts/.venv'
        }
    }
}
