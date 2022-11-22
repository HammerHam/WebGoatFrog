pipeline {
    agent any

    stages {
        stage('Do Nothing') {
            steps {
                echo 'Doing Nothing..'
            }
        }
        stage('Test Nothing') {
            steps {
                echo 'Testing Nothing..'
            }
        }
        stage('Deploy') {
            steps {
         echo 'Deploying....'          
         sh '''#!/bin/bash
                 mvn deploy
         '''
            }
        }
    }
}
