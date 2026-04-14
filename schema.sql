--
-- PostgreSQL database dump
--

\restrict eW8MbSOdMsdGL6WT862HAJ2PyxXQESqkMN29aKeG04bFRTI1R9qZ5fe05ywdRUf

-- Dumped from database version 15.16 (Debian 15.16-0+deb12u1)
-- Dumped by pg_dump version 15.16 (Debian 15.16-0+deb12u1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: increment_connection_counter(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.increment_connection_counter() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    UPDATE connection_counter SET total_connections = total_connections + 1;
    RETURN NEW;
END;
$$;


--
-- Name: log_suspicious_connection(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.log_suspicious_connection() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.serror_rate > 0.5 THEN
        INSERT INTO suspicious_audit(connection_id, serror_rate)
        VALUES (NULL, NEW.serror_rate);
    END IF;
    RETURN NEW;
END;
$$;


--
-- Name: prevent_negative_duration(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.prevent_negative_duration() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.duration < 0 THEN
        RAISE EXCEPTION 'Duration cannot be negative: %', NEW.duration;
    END IF;
    RETURN NEW;
END;
$$;


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: attack_categories; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.attack_categories (
    category_id integer NOT NULL,
    category_name character varying NOT NULL
);


--
-- Name: attack_categories_category_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.attack_categories_category_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: attack_categories_category_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.attack_categories_category_id_seq OWNED BY public.attack_categories.category_id;


--
-- Name: attack_types; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.attack_types (
    attack_id integer NOT NULL,
    attack_name character varying NOT NULL,
    category_id integer NOT NULL
);


--
-- Name: attack_types_attack_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.attack_types_attack_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: attack_types_attack_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.attack_types_attack_id_seq OWNED BY public.attack_types.attack_id;


--
-- Name: attacks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.attacks (
    attack_name character varying(30) NOT NULL,
    attack_category character varying(20) NOT NULL
);


--
-- Name: conn_proto_service; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.conn_proto_service (
    log_id integer NOT NULL,
    protocol character varying(10) NOT NULL,
    service character varying(30) NOT NULL
);


--
-- Name: conn_protocols; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.conn_protocols (
    log_id integer NOT NULL,
    protocol_id integer NOT NULL
);


--
-- Name: conn_services; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.conn_services (
    log_id integer NOT NULL,
    service_id integer NOT NULL
);


--
-- Name: connection_counter; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.connection_counter (
    total_connections bigint
);


--
-- Name: connections; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.connections (
    duration bigint,
    src_bytes bigint,
    land boolean,
    logged_in boolean,
    count bigint,
    srv_count bigint,
    serror_rate double precision,
    rerror_rate double precision,
    same_srv_rate double precision,
    difficulty_level bigint,
    protocol_id bigint,
    service_id bigint,
    flag_id bigint,
    attack_id bigint,
    destination_id integer
);


--
-- Name: connections_2nf; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.connections_2nf (
    log_id integer NOT NULL,
    duration integer,
    src_bytes bigint,
    flag character varying(10),
    attack_name character varying(30),
    attack_category character varying(20),
    dst_host_count smallint,
    dst_bytes bigint
);


--
-- Name: connections_3nf; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.connections_3nf (
    log_id integer NOT NULL,
    duration integer,
    src_bytes bigint,
    flag character varying(10),
    attack_name character varying(30),
    dst_host_count smallint,
    dst_bytes bigint
);


--
-- Name: destination; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.destination (
    destination_id integer NOT NULL,
    dst_bytes bigint,
    dst_host_count smallint,
    dst_host_srv_count smallint,
    dst_host_same_srv_rate real,
    dst_host_diff_srv_rate real,
    dst_host_serror_rate real,
    CONSTRAINT destination_dst_host_diff_srv_rate_check CHECK (((dst_host_diff_srv_rate >= (0)::double precision) AND (dst_host_diff_srv_rate <= (1)::double precision))),
    CONSTRAINT destination_dst_host_same_srv_rate_check CHECK (((dst_host_same_srv_rate >= (0)::double precision) AND (dst_host_same_srv_rate <= (1)::double precision))),
    CONSTRAINT destination_dst_host_serror_rate_check CHECK (((dst_host_serror_rate >= (0)::double precision) AND (dst_host_serror_rate <= (1)::double precision)))
);


--
-- Name: destination_destination_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.destination_destination_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: destination_destination_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.destination_destination_id_seq OWNED BY public.destination.destination_id;


--
-- Name: flags; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.flags (
    flag_id integer NOT NULL,
    flag_value character varying NOT NULL
);


--
-- Name: flags_flag_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.flags_flag_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: flags_flag_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.flags_flag_id_seq OWNED BY public.flags.flag_id;


--
-- Name: high_risk_connections; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.high_risk_connections AS
 SELECT connections.duration,
    connections.src_bytes,
    connections.land,
    connections.logged_in,
    connections.count,
    connections.srv_count,
    connections.serror_rate,
    connections.rerror_rate,
    connections.same_srv_rate,
    connections.difficulty_level,
    connections.protocol_id,
    connections.service_id,
    connections.flag_id,
    connections.attack_id,
    connections.destination_id
   FROM public.connections
  WHERE ((COALESCE(connections.serror_rate, (0)::double precision) > (0.3)::double precision) OR (COALESCE(connections.rerror_rate, (0)::double precision) > (0.3)::double precision));


--
-- Name: high_traffic_connections; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.high_traffic_connections AS
 SELECT connections.duration,
    connections.src_bytes,
    connections.land,
    connections.logged_in,
    connections.count,
    connections.srv_count,
    connections.serror_rate,
    connections.rerror_rate,
    connections.same_srv_rate,
    connections.difficulty_level,
    connections.protocol_id,
    connections.service_id,
    connections.flag_id,
    connections.attack_id,
    connections.destination_id
   FROM public.connections
  WHERE (connections.src_bytes > 100000);


--
-- Name: network_log_1nf; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.network_log_1nf (
    log_id integer NOT NULL,
    protocol character varying(10) NOT NULL,
    service character varying(30) NOT NULL,
    duration integer,
    src_bytes bigint,
    flag character varying(10),
    attack_name character varying(30),
    attack_category character varying(20),
    dst_host_count smallint,
    dst_bytes bigint
);


--
-- Name: network_log_raw; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.network_log_raw (
    log_id integer NOT NULL,
    duration integer,
    src_bytes bigint,
    protocols_used character varying(50),
    services_used character varying(100),
    flag character varying(10),
    attack_name character varying(30),
    attack_category character varying(20),
    dst_host_count smallint,
    dst_bytes bigint
);


--
-- Name: network_log_raw_log_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.network_log_raw_log_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: network_log_raw_log_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.network_log_raw_log_id_seq OWNED BY public.network_log_raw.log_id;


--
-- Name: protocol_types; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.protocol_types (
    protocol_id integer NOT NULL,
    protocol_name character varying NOT NULL
);


--
-- Name: protocol_types_protocol_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.protocol_types_protocol_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: protocol_types_protocol_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.protocol_types_protocol_id_seq OWNED BY public.protocol_types.protocol_id;


--
-- Name: services; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.services (
    service_id integer NOT NULL,
    service_name character varying NOT NULL
);


--
-- Name: services_service_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.services_service_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: services_service_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.services_service_id_seq OWNED BY public.services.service_id;


--
-- Name: successful_logins; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.successful_logins AS
 SELECT connections.duration,
    connections.src_bytes,
    connections.land,
    connections.logged_in,
    connections.count,
    connections.srv_count,
    connections.serror_rate,
    connections.rerror_rate,
    connections.same_srv_rate,
    connections.difficulty_level,
    connections.protocol_id,
    connections.service_id,
    connections.flag_id,
    connections.attack_id,
    connections.destination_id
   FROM public.connections
  WHERE (connections.logged_in = true);


--
-- Name: suspicious_audit; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.suspicious_audit (
    audit_id integer NOT NULL,
    connection_id bigint,
    serror_rate double precision,
    logged_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: suspicious_audit_audit_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.suspicious_audit_audit_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: suspicious_audit_audit_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.suspicious_audit_audit_id_seq OWNED BY public.suspicious_audit.audit_id;


--
-- Name: suspicious_logs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.suspicious_logs (
    log_id integer NOT NULL,
    connection_id bigint,
    attack_name character varying,
    category_name character varying,
    log_time timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: suspicious_logs_log_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.suspicious_logs_log_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: suspicious_logs_log_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.suspicious_logs_log_id_seq OWNED BY public.suspicious_logs.log_id;


--
-- Name: attack_categories category_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attack_categories ALTER COLUMN category_id SET DEFAULT nextval('public.attack_categories_category_id_seq'::regclass);


--
-- Name: attack_types attack_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attack_types ALTER COLUMN attack_id SET DEFAULT nextval('public.attack_types_attack_id_seq'::regclass);


--
-- Name: destination destination_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.destination ALTER COLUMN destination_id SET DEFAULT nextval('public.destination_destination_id_seq'::regclass);


--
-- Name: flags flag_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.flags ALTER COLUMN flag_id SET DEFAULT nextval('public.flags_flag_id_seq'::regclass);


--
-- Name: network_log_raw log_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.network_log_raw ALTER COLUMN log_id SET DEFAULT nextval('public.network_log_raw_log_id_seq'::regclass);


--
-- Name: protocol_types protocol_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.protocol_types ALTER COLUMN protocol_id SET DEFAULT nextval('public.protocol_types_protocol_id_seq'::regclass);


--
-- Name: services service_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.services ALTER COLUMN service_id SET DEFAULT nextval('public.services_service_id_seq'::regclass);


--
-- Name: suspicious_audit audit_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.suspicious_audit ALTER COLUMN audit_id SET DEFAULT nextval('public.suspicious_audit_audit_id_seq'::regclass);


--
-- Name: suspicious_logs log_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.suspicious_logs ALTER COLUMN log_id SET DEFAULT nextval('public.suspicious_logs_log_id_seq'::regclass);


--
-- Name: attack_categories attack_categories_category_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attack_categories
    ADD CONSTRAINT attack_categories_category_name_key UNIQUE (category_name);


--
-- Name: attack_categories attack_categories_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attack_categories
    ADD CONSTRAINT attack_categories_pkey PRIMARY KEY (category_id);


--
-- Name: attack_types attack_types_attack_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attack_types
    ADD CONSTRAINT attack_types_attack_name_key UNIQUE (attack_name);


--
-- Name: attack_types attack_types_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attack_types
    ADD CONSTRAINT attack_types_pkey PRIMARY KEY (attack_id);


--
-- Name: attacks attacks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attacks
    ADD CONSTRAINT attacks_pkey PRIMARY KEY (attack_name);


--
-- Name: conn_proto_service conn_proto_service_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.conn_proto_service
    ADD CONSTRAINT conn_proto_service_pkey PRIMARY KEY (log_id, protocol, service);


--
-- Name: conn_protocols conn_protocols_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.conn_protocols
    ADD CONSTRAINT conn_protocols_pkey PRIMARY KEY (log_id, protocol_id);


--
-- Name: conn_services conn_services_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.conn_services
    ADD CONSTRAINT conn_services_pkey PRIMARY KEY (log_id, service_id);


--
-- Name: connections_2nf connections_2nf_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.connections_2nf
    ADD CONSTRAINT connections_2nf_pkey PRIMARY KEY (log_id);


--
-- Name: connections_3nf connections_3nf_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.connections_3nf
    ADD CONSTRAINT connections_3nf_pkey PRIMARY KEY (log_id);


--
-- Name: destination destination_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.destination
    ADD CONSTRAINT destination_pkey PRIMARY KEY (destination_id);


--
-- Name: flags flags_flag_value_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.flags
    ADD CONSTRAINT flags_flag_value_key UNIQUE (flag_value);


--
-- Name: flags flags_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.flags
    ADD CONSTRAINT flags_pkey PRIMARY KEY (flag_id);


--
-- Name: network_log_1nf network_log_1nf_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.network_log_1nf
    ADD CONSTRAINT network_log_1nf_pkey PRIMARY KEY (log_id, protocol, service);


--
-- Name: network_log_raw network_log_raw_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.network_log_raw
    ADD CONSTRAINT network_log_raw_pkey PRIMARY KEY (log_id);


--
-- Name: protocol_types protocol_types_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.protocol_types
    ADD CONSTRAINT protocol_types_pkey PRIMARY KEY (protocol_id);


--
-- Name: protocol_types protocol_types_protocol_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.protocol_types
    ADD CONSTRAINT protocol_types_protocol_name_key UNIQUE (protocol_name);


--
-- Name: services services_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.services
    ADD CONSTRAINT services_pkey PRIMARY KEY (service_id);


--
-- Name: services services_service_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.services
    ADD CONSTRAINT services_service_name_key UNIQUE (service_name);


--
-- Name: suspicious_audit suspicious_audit_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.suspicious_audit
    ADD CONSTRAINT suspicious_audit_pkey PRIMARY KEY (audit_id);


--
-- Name: suspicious_logs suspicious_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.suspicious_logs
    ADD CONSTRAINT suspicious_logs_pkey PRIMARY KEY (log_id);


--
-- Name: destination unique_destination; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.destination
    ADD CONSTRAINT unique_destination UNIQUE (dst_bytes, dst_host_count, dst_host_srv_count, dst_host_same_srv_rate, dst_host_diff_srv_rate, dst_host_serror_rate);


--
-- Name: idx_connections_destination; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_connections_destination ON public.connections USING btree (destination_id);


--
-- Name: idx_destination_metrics; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_destination_metrics ON public.destination USING btree (dst_host_count, dst_host_srv_count, dst_host_serror_rate);


--
-- Name: connections trg_increment_counter; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_increment_counter AFTER INSERT ON public.connections FOR EACH ROW EXECUTE FUNCTION public.increment_connection_counter();


--
-- Name: connections trg_log_suspicious; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_log_suspicious AFTER INSERT ON public.connections FOR EACH ROW EXECUTE FUNCTION public.log_suspicious_connection();


--
-- Name: connections trg_prevent_negative_duration; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_prevent_negative_duration BEFORE INSERT OR UPDATE ON public.connections FOR EACH ROW EXECUTE FUNCTION public.prevent_negative_duration();


--
-- Name: attack_types attack_types_category_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attack_types
    ADD CONSTRAINT attack_types_category_id_fkey FOREIGN KEY (category_id) REFERENCES public.attack_categories(category_id) ON UPDATE CASCADE ON DELETE RESTRICT;


--
-- Name: conn_proto_service conn_proto_service_log_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.conn_proto_service
    ADD CONSTRAINT conn_proto_service_log_id_fkey FOREIGN KEY (log_id) REFERENCES public.connections_2nf(log_id);


--
-- Name: conn_protocols conn_protocols_log_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.conn_protocols
    ADD CONSTRAINT conn_protocols_log_id_fkey FOREIGN KEY (log_id) REFERENCES public.connections_3nf(log_id);


--
-- Name: conn_protocols conn_protocols_protocol_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.conn_protocols
    ADD CONSTRAINT conn_protocols_protocol_id_fkey FOREIGN KEY (protocol_id) REFERENCES public.protocol_types(protocol_id);


--
-- Name: conn_services conn_services_log_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.conn_services
    ADD CONSTRAINT conn_services_log_id_fkey FOREIGN KEY (log_id) REFERENCES public.connections_3nf(log_id);


--
-- Name: conn_services conn_services_service_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.conn_services
    ADD CONSTRAINT conn_services_service_id_fkey FOREIGN KEY (service_id) REFERENCES public.services(service_id);


--
-- Name: connections_3nf connections_3nf_attack_name_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.connections_3nf
    ADD CONSTRAINT connections_3nf_attack_name_fkey FOREIGN KEY (attack_name) REFERENCES public.attacks(attack_name);


--
-- Name: connections fk_connections_destination; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.connections
    ADD CONSTRAINT fk_connections_destination FOREIGN KEY (destination_id) REFERENCES public.destination(destination_id) ON UPDATE CASCADE ON DELETE SET NULL;


--
-- PostgreSQL database dump complete
--

\unrestrict eW8MbSOdMsdGL6WT862HAJ2PyxXQESqkMN29aKeG04bFRTI1R9qZ5fe05ywdRUf

