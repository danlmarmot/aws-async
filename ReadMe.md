Simple demo project for using asyncio with AWS.

Why?  Boto3 is synchronous; under the hood it relies on urllib3.  Because of this, it takes quite a bit of time to make calls across all AWS regions.  You might want to do this to create an inventory of all EC2 instances, for instance.

Since boto3 just wraps REST-like HTTP calls to various AWS services, this was to see how difficult it is to do for time-consuming calls.

## What was the inspiration?

Two blog posts in particular pointed the way:

- https://www.mathewmarcus.com/blog/asynchronous-aws-api-requests-with-asyncio.html, which showed how to make requests
- https://charemza.name/blog/posts/aws/python/you-might-not-need-boto-3/, which showed how to remove boto3 entirely
 
The AWS documentation had three really good Python examples of signing requests as well: https://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html

## What was the approach and what was discovered??

1. The simple EC2 describeRegions API was used first.  A synchronous version using requests was written first to validate API signing, then the async version was added.
1. The EC2 describeSecurityGroups API was done next--every EC2 region has a default security group, and there's no charge to query for it either.
1. The aiohttp library has somewhat different usage than requests.  
1. AWS prefers and recommends HTTP POST for almost all API calls, as there isn't a limitation on how much data you can send up with POST
1. Signing is very stable--but for regions other than us-east-1, it was slightly tricky to get valid signed requests generated that included the region name.
1. Results from the EC2 API come back as XML, which needs parsing.  While additional and third-party libraries were avoided wherever possible, adding xmltodict sped things up greatly.  This exercise isn't about XML parsing, but rather about using asyncio
1. The AWS describe security groups API will return a dictionary if there's just one group, and a list if there's more than one.  Just an inconsistency to handle.
1. Python black was used for canonical formatting
 

## What's next or not done at all?
1. Add a synchronous call to get security groups across all the regions, and compare timings
1. Figure out what the aiohttp docs mean when they say that ClientSession should be global for an app for better connection pool reuse--and why there's little in the way of code samples for this.
2. Error handling is minimal
3. Perhaps parse out the security groups rules into a more accessible format
