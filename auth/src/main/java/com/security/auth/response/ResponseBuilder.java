package com.security.auth.response;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.security.auth.response.Response;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Builder
public class ResponseBuilder<T> implements Response {
    @JsonProperty("success")
    private boolean success;
    @JsonProperty("response")
    private T response;
}
