package enterprises.neuland.keycloak.fake_email_mapper;

import com.google.auto.service.AutoService;
import org.keycloak.models.*;
import org.keycloak.protocol.ProtocolMapper;
import org.keycloak.protocol.oidc.mappers.*;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.IDToken;

import java.util.ArrayList;
import java.util.List;

@AutoService(ProtocolMapper.class)
public class FakeEmailOidcMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();

    public static final String DOMAIN_CONFIG = "domain";

    static {
        OIDCAttributeMapperHelper.addTokenClaimNameConfig(configProperties);

        ProviderConfigProperty domain = new ProviderConfigProperty();
        domain.setType(ProviderConfigProperty.STRING_TYPE);
        domain.setName(DOMAIN_CONFIG);
        domain.setLabel("domain");
        domain.setHelpText("Domain name to use for fake email address generation of kind username @ domain");
        configProperties.add(domain);

        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, FakeEmailOidcMapper.class);
    }

    public static final String PROVIDER_ID = "fake-email-oidc-mapper";

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getDisplayType() {
        return "Fake Email Mapper";
    }

    @Override
    public String getHelpText() {
        return "Adds a mail claim of the format <username>@<domain>.";
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession, KeycloakSession keycloakSession, ClientSessionContext clientSessionCtx) {
        UserModel user = userSession.getUser();
        String domain = mappingModel.getConfig().get(DOMAIN_CONFIG);
        if (domain == null) return;
        String claimValue = user.getUsername() + "@" + domain;
        OIDCAttributeMapperHelper.mapClaim(token, mappingModel, claimValue);
    }

    @Override
    protected void setClaim(AccessTokenResponse accessTokenResponse, ProtocolMapperModel mappingModel, UserSessionModel userSession, KeycloakSession keycloakSession, ClientSessionContext clientSessionCtx) {
        UserModel user = userSession.getUser();
        String domain = mappingModel.getConfig().get(DOMAIN_CONFIG);
        if (domain == null) return;
        String claimValue = user.getUsername() + "@" + domain;
        OIDCAttributeMapperHelper.mapClaim(accessTokenResponse, mappingModel, claimValue);
    }
}
