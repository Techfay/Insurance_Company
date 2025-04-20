#!/bin/bash

TOPIC_ARN="arn:aws:sns:us-east-1:471112755998:PolicySaleNotifications"

# List all subscriptions for the topic
aws sns list-subscriptions-by-topic --topic-arn "$TOPIC_ARN" --query 'Subscriptions[].SubscriptionArn' --output text | while read -r subscription_arn; do
    # Unsubscribe each subscription
    echo "Deleting subscription: $subscription_arn"
    aws sns unsubscribe --subscription-arn "$subscription_arn"
done

echo "All subscriptions have been deleted."

