from common import *

url = '/sdnservice/control'

class SDNServiceAPI(ControllerBase):
    """Represents the REST API avaailable through RYU for SDNEngine."""

    def __init__(self, req, link, data, **config):
        super(SDNServiceAPI, self).__init__(req, link, data, **config)
        self.sdnservice = data[REST_API_NAME]


    @route('sdnservice', url, methods=['PUT'], requirements={})
    def putControl(self, req, **kwargs):
        if len(self.sdnservice.dp) == 0:
            self.sdnservice.logger.debug("SDNServiceAPI.putControl: No datapath is yet registered with the controller, skipping request.")
            return Response(content_type="text/plain", body="no-datapath-registered")

        if len(self.sdnservice.dp) > 1:
            self.sdnservice.logger.debug("SDNServiceAPI.putControl: Multiple datapaths registered... not sure which one you want the request sent to... so sending it to the first one.")

        for dp in self.sdnservice.dp:
            result = self.sdnservice.dp[dp]['engine'].apiControl(req.body)
            return Response(content_type="text/plain", body=result)

