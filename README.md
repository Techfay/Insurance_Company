######Insurance Based Management System ########

This is a cloud-native, event-driven **Insurance Management System** built in **Python** using **Django** and deployed on **AWS**. 
The system allows customers to browse and apply for insurance, submit claims, and interact with agents and admins. Real-time notifications, secure cloud storage, and monitoring are integrated with **AWS services**.

A comprehensive, cloud-integrated solution for managing insurance policies, claims, and customer interactions, built with Python and AWS.
From browsing policies and submitting claims to real-time notifications and secure file storage, This web application offers a seamless, scalable solution for modern insurance management.

------------------
## Features

###  User Side (Customer)
- Register/Login securely
- Browse and purchase insurance policies
- Calculate premiums (custom Python library)
- Submit/view insurance claims with document uploads
- Receive claim approval/rejection via email (SNS)
- Link for Custom Python Library for Premium Calculator (https://pypi.org/project/premium-calculator-shivangi/)


###  Agent Dashboard
- View assigned policies
- Review customer claims
- Manage customer records
- Analyze sales performance

###  Admin Dashboard
- Manage policies, claims, users
- Create/update/delete policies
- Approve/reject claims
- View analytics, system activity, and performance

-----------------

## AWS Services Used

| AWS Service                    | Purpose                                                                  |
|--------------------------------|--------------------------------------------------------------------------|
| **Elastic Beanstalk**          | Deploys and manages the Python app with auto-scaling and load balancing  |
| **Amazon RDS (PostgreSQL)**    | Stores structured relational data such as user information, policies, and claims |
| **Amazon DynamoDB**            | Stores fast-access, non-relational data like customer-policy mappings and claim metadata |
| **Amazon S3**                  | Stores uploaded claim documents and auto-generated policy PDFs           |
| **Amazon SNS**                 | Sends real-time claim notifications (email/SMS)                          |
| **AWS Lambda**                 | Generates PDF documents after policy purchase                            |
| **Amazon CloudWatch**          | Monitors application logs, metrics, and alerts                           |
| **IAM Roles**                  | Manages secure, role-based access to AWS services                        |

---------------

## Tech Stack

- **Programming Language**: Python 3
- **Framework**: Django
- **Database**: SQLite (Development)
- **Database**: RDS (PostgreSQL), DynamoDB
- **Cloud Services**: AWS (S3, SNS, Lambda, Elastic Beanstalk, CloudWatch, IAM)
- **Monitoring**: CloudWatch for performance and health monitoring

----------------

## How It Works - Workflow

1. **Customer submits claim** → Claim data is stored in **DynamoDB**
2. **Claim documents uploaded** → Stored in **Amazon S3**
3. **SNS publishes notification** → User and admin receive updates
4. **PDF policy generated** → Stored in **S3** via **Lambda**
5. **All logs and activities tracked** → Monitored via **CloudWatch**

----------------

## Deployment

This app is hosted on **AWS Elastic Beanstalk**, allowing easy scaling and management of the application without needing to handle infrastructure directly.

------------------

## Security & Best Practices

- **AWS IAM roles** for managing secure access to services
- **Environment variables** are used for storing sensitive keys, ensuring no credentials are hard-coded
- **S3 Bucket policies** to enforce encryption and access restrictions
- **IAM role-based access control** for managing which services and users have access to what.

-----------------

## Learnings & Outcomes

- Successfully integrated multiple **AWS services** into a cloud-native Django app.
- Gained hands-on experience with **Elastic Beanstalk** for deployment, scaling, and monitoring.
- Integrated **SNS** for real-time notifications and **CloudWatch** for logging and monitoring.
- Learned how to implement **AWS Lambda** for serverless operations (PDF generation).
- Designed a solution with both **RDS (structured)** and **DynamoDB (NoSQL)** for optimal data handling.

---------------

##########  How to Run Locally - Set Up ###########

Prerequisites:
- Python 3.10+ (Make sure Python is installed by running python --version)
-pip (Python package manager)
-Virtual Environment (Optional, but recommended)
-AWS CLI (for AWS credentials management)

## Instructions to follow

Step.1 Clone the repository.

git clone https://github.com/Techfay/Insurance_Company.git

cd Insurance_Company

Step.2 Set up a virtual environment (optional, but recommended).

For Windows:
- python -m venv venv
- venv\Scripts\activate

For macOS/Linux:
- python3 -m venv venv
- source venv/bin/activate

Step.3 Install dependencies.
- pip install -r requirements.txt

Step.4 Apply migrations.
- python manage.py migrate

Step.5 Create a superuser (Admin access)
- python manage.py createsuperuser

Step.6 Run the Django server
- python manage.py runserver

----------------------

## Author

**Shivangi Pandey**  
📧 Email: shivangipandeydt.126@gmail.com  
🔗 GitHub: [github.com/Techfay](https://github.com/Techfay)

---------------------

## License

This project is licensed under the **MIT License**. See the `LICENSE` file for details.







