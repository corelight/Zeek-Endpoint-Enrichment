module EndpointEnrichment;

export {
        ## Enables the logging of endpoint details to all logs with an "id" field.
        option extra_logging_all = F;
        ## Enables the logging of endpoint details to the conn log.
        option extra_logging_conn = T;
        ## Enables the logging of endpoint details to the Known-entities.
        option extra_logging_known = F;
}
