"""External bridge mechanisms: real PostgreSQL, explicitly synthetic HTTP issuer.

This does not install or qualify OpenBao. The HTTP fixture performs the reviewed
password-free creation/renew/revoke SQL statements through an actual restricted
issuer login, then returns a generated synthetic password over local HTTP.
"""
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import subprocess
import threading
import time
import unittest
from unittest.mock import patch

import test_credential_kernel as fixture
from hobnail.client import Client, Denied, PsqlTransport, TransportError
from hobnail.credentials import (CredentialBroker, CredentialError, CredentialRequest, OpenBaoCredentialProvider,
                                  PostgresExternalBridge, Secret, configure_openbao_postgres)


class ExternalCredentialTests(unittest.TestCase):
    client = fixture.CredentialKernelTests.client
    request = fixture.CredentialKernelTests.request

    def setUp(self):
        fixture.CredentialKernelTests.setUp(self)
        self.issuer = self.provider.issue(CredentialRequest(99999, self.profile.name, "worker", "worker", 60))
        self.issuer_transport = self.client(self.issuer.login, self.issuer.password.reveal()).transport
        self.templates = configure_openbao_postgres(self.admin_transport, profile=self.profile.name,
            issuer_login=self.issuer.login, backend_role="worker", issuance_ttl_seconds=10)
        self.cluster.psql("ALTER SYSTEM SET log_statement='all'")
        self.cluster.psql("SELECT pg_reload_conf()")
        for _ in range(50):
            if self.cluster.psql("SHOW log_statement").stdout.strip()=="all": break
            time.sleep(.01)
        else: self.fail("statement logging did not activate")
        self.calls=[]; self.material={}; self.created=[]; self.mode="normal"; self.handler_errors=[]
        outer=self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args): pass
            def do_GET(self): self.respond()
            def do_PUT(self): self.respond()
            def respond(self):
                data=self.rfile.read(int(self.headers.get('Content-Length','0')))
                payload=json.loads(data) if data else {}
                outer.calls.append((self.command,self.path,payload))
                try:
                    if self.command=='GET':
                        login='hbx_'+secrets.token_hex(16)
                        reference='database/creds/worker/'+secrets.token_hex(16)
                        password=secrets.token_urlsafe(32)
                        if outer.mode=='existing_response':
                            login=outer.existing_login
                        else:
                            outer.issuer_transport.execute_sql(
                                f"SELECT hobnail_external.create_role('worker-basic','{login}',clock_timestamp()+interval '10 seconds');")
                            outer.created.append(login)
                        outer.material[reference]=(login,password)
                        if outer.mode=='lost_http':
                            self.send_response(503); self.end_headers(); return
                        response={'lease_id':reference,'lease_duration':10,'renewable':True,
                                  'data':{'username':login,'password':password}}
                    elif self.path=='/v1/sys/leases/renew':
                        reference=payload['lease_id']; login,_=outer.material[reference]
                        # Real OpenBao's duration endpoint accepts exact unit
                        # strings and returns integer lease_duration seconds.
                        # Enforce the production wire format instead of echoing
                        # a request value into a differently typed response.
                        increment=payload['increment']
                        if (not isinstance(increment,str) or not increment.endswith('s')
                                or not increment[:-1].isdigit()):
                            raise AssertionError('expected explicit duration seconds')
                        ttl=int(increment[:-1])
                        outer.issuer_transport.execute_sql(
                            f"SELECT hobnail_external.renew_role('worker-basic','{login}',clock_timestamp()+make_interval(secs=>{ttl}));")
                        response={'lease_id':reference,'lease_duration':ttl,'renewable':True}
                    else:
                        if outer.mode=='revoke_unavailable':
                            self.send_response(503); self.end_headers(); return
                        if outer.mode=='revoke_queued':
                            self.send_response(202); self.end_headers(); return
                        if payload.get('sync') is not True:
                            raise AssertionError('synchronous revoke was not requested')
                        login,_=outer.material[payload['lease_id']]
                        outer.issuer_transport.execute_sql(f"SELECT hobnail_external.revoke_role('worker-basic','{login}');")
                        response={}
                    self.send_response(200); self.end_headers()
                    self.wfile.write(json.dumps(response).encode())
                except Exception as error:
                    outer.handler_errors.append(type(error).__name__)
                    self.send_response(500); self.end_headers()
        self.server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True); self.thread.start()
        self.addCleanup(self.close_server)
        self.bridge=PostgresExternalBridge(self.admin_transport,self.provider_client)
        self.bao=self.new_provider()
        self.broker=CredentialBroker(self.provider_client,self.bao)

    def close_server(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=5)

    def new_provider(self,bridge=None):
        profile=replace(self.profile,backend_role='worker')
        return OpenBaoCredentialProvider(address=f'http://127.0.0.1:{self.server.server_port}',
            token=Secret('synthetic-http-token'),provider_id='provider',profiles={profile.name:profile},
            allow_insecure_loopback=True,bridge=bridge or self.bridge)

    def issue(self):
        return self.broker.issue_request(self.request())

    def test_whole_issuance_renewal_revocation_and_actual_authentication(self):
        lease=self.issue()
        actor=self.client(lease.login,lease.password.reveal())
        self.assertEqual(actor.require('credential.get',{'credential_id':lease.credential_id})['data']['principal'],'worker')
        with self.assertRaises(TransportError): self.client(lease.login,'wrong-password').transport.execute_sql('SELECT 1')
        self.assertEqual(self.bridge.data(lease.request_id)['expires_at'],lease.expires_at)
        self.worker.require('credential.renew_requested',{'credential_id':lease.credential_id,'ttl_seconds':30})
        renewed=self.broker.renew_requested(lease.credential_id)
        self.assertEqual(self.bridge.data(lease.request_id)['expires_at'],renewed.expires_at)
        self.assertGreater(renewed.expires_at,lease.expires_at)
        self.worker.require('credential.revoke_requested',{'credential_id':lease.credential_id})
        self.assertEqual(self.broker.revoke_requested(lease.credential_id).result,'confirmed')
        with self.assertRaises(TransportError): actor.transport.execute_sql('SELECT 1')
        data=self.bridge.data(lease.request_id)
        self.assertEqual((data['state'],data['provider_cleanup'],data['active_sessions']),('closed','confirmed',0))
        self.assertEqual(self.handler_errors,[])

    def test_templates_and_real_statement_log_contain_no_password_or_scram_verifier(self):
        lease=self.issue()
        for statement in self.templates.values(): self.assertNotIn('{{password}}',statement)
        self.assertNotIn('password',self.templates['creation_statements'].lower())
        log=(self.cluster.root/'server.log').read_text()
        self.assertIn('hobnail_external.create_role',log)
        self.assertIn('COPY pg_temp.hobnail_external_material',log)
        self.assertNotIn(lease.password.reveal(),log)
        self.assertNotIn('SCRAM-SHA-256$4096:',log)
        rows=self.cluster.psql('SELECT jsonb_agg(to_jsonb(t)) FROM hobnail.external_creations t').stdout
        self.assertNotIn(lease.password.reveal(),rows)
        self.assertIsNone(json.loads(self.admin_transport.execute_sql(
            f"SELECT to_json(shobj_description((SELECT oid FROM pg_roles WHERE rolname='{lease.login}'),'pg_authid'));").strip() or 'null'))

    def test_existing_role_response_is_not_adopted_or_changed(self):
        self.existing_login='hbx_'+'a'*32
        self.admin_transport.execute_sql(f'CREATE ROLE {self.existing_login} NOLOGIN;')
        self.mode='existing_response'
        request=self.request()
        with self.assertRaises((CredentialError,Denied)): self.broker.issue_request(request)
        self.assertEqual(self.admin_transport.execute_sql(f"SELECT rolcanlogin FROM pg_roles WHERE rolname='{self.existing_login}'").strip(),'f')
        self.assertEqual(self.bridge.data(request)['state'],'prepared')
        self.assertEqual(self.cluster.psql('SELECT count(*) FROM hobnail.external_creations').stdout.strip(),'0')

    def test_hook_rejects_existing_login_and_unauthorized_issuer_and_missing_attempt(self):
        login='hbx_'+'b'*32
        call=f"SELECT hobnail_external.create_role('worker-basic','{login}',clock_timestamp()+interval '10 seconds')"
        with self.assertRaises(TransportError): self.issuer_transport.execute_sql(call)
        self.bridge.prepare(self.request())
        with self.assertRaises(TransportError): self.worker.transport.execute_sql(call)
        self.admin_transport.execute_sql(f'CREATE ROLE {login} NOLOGIN')
        with self.assertRaises(TransportError): self.issuer_transport.execute_sql(call)
        self.assertEqual(self.cluster.psql('SELECT count(*) FROM hobnail.external_creations').stdout.strip(),'0')

    def test_pending_request_serializes_http_and_cannot_be_replayed(self):
        first=self.request('first'); second=self.request('second')
        self.bridge.prepare(first)
        with self.assertRaises(Denied): self.bridge.prepare(second)
        with self.assertRaises(CredentialError): self.broker.issue_request(first)
        self.assertEqual(self.calls,[])
        self.assertEqual(self.broker.reconcile_request(first).result,'pending')
        self.assertEqual(self.bridge.data(first)['state'],'prepared')
        with self.assertRaises(Denied): self.bridge.prepare(second)
        delayed='hbx_'+'d'*32
        self.issuer_transport.execute_sql(f"SELECT hobnail_external.create_role('worker-basic','{delayed}',clock_timestamp()+interval '10 seconds')")
        self.assertEqual(self.bridge.data(first)['login'],delayed)
        self.assertEqual(self.broker.reconcile_request(first).result,'pending')
        self.assertEqual(self.bridge.data(first)['state'],'closed')
        self.assertIsNotNone(self.broker.issue_request(second).credential_id)

    def test_hook_inventory_rejects_public_execution_drift(self):
        self.admin_transport.execute_sql('GRANT EXECUTE ON FUNCTION hobnail_external.create_role(text,text,timestamptz) TO PUBLIC')
        with self.assertRaisesRegex(CredentialError,'drift'): self.broker.issue_request(self.request())
        self.assertEqual(self.calls,[])

    def test_hook_inventory_rejects_schema_creation_privilege_drift(self):
        self.admin_transport.execute_sql('GRANT CREATE ON SCHEMA hobnail_external TO PUBLIC')
        with self.assertRaises(CredentialError): self.broker.issue_request(self.request())
        self.assertEqual(self.calls,[])

    def test_preprivileged_issuer_is_refused_before_hook_installation(self):
        other=fixture.CredentialKernelTests('runTest')
        other.setUp(); self.addCleanup(other.doCleanups)
        issuer=other.provider.issue(CredentialRequest(99998,other.profile.name,'worker','worker',60))
        other.admin_transport.execute_sql(f'GRANT SELECT ON hobnail.credential_requests TO "{issuer.login}"')
        with self.assertRaises(CredentialError):
            configure_openbao_postgres(other.admin_transport,profile=other.profile.name,issuer_login=issuer.login,
                                      backend_role='worker',issuance_ttl_seconds=10)
        self.assertEqual(other.admin_transport.execute_sql("SELECT to_regnamespace('hobnail_external') IS NULL").strip(),'t')
        other.admin_transport.execute_sql(f'REVOKE SELECT ON hobnail.credential_requests FROM "{issuer.login}"')
        self.assertIn('creation_statements',configure_openbao_postgres(other.admin_transport,profile=other.profile.name,
                    issuer_login=issuer.login,backend_role='worker',issuance_ttl_seconds=10))

    def test_lost_http_reply_is_recovered_without_new_issuance_or_secret(self):
        self.mode='lost_http'; request=self.request()
        with self.assertRaises(CredentialError): self.broker.issue_request(request)
        data=self.bridge.data(request)
        self.assertEqual((data['state'],data['login_enabled'],data['provider_cleanup']),('closed',False,'unavailable'))
        self.assertEqual(len(self.created),1)
        restarted=CredentialBroker(self.provider_client,self.new_provider())
        self.assertEqual(restarted.reconcile_request(request).result,'pending')
        with self.assertRaises(CredentialError): restarted.issue_request(request)
        self.assertEqual(len(self.created),1)

    def test_lost_kernel_binding_reply_reconciles_both_channels(self):
        from test_credential_recovery import LostReply
        request=self.request()
        broker=CredentialBroker(LostReply(self.provider_client,'credential.issued'),self.bao)
        with self.assertRaises(TransportError): broker.issue_request(request)
        data=self.bridge.data(request)
        self.assertEqual((data['state'],data['provider_cleanup'],data['login_enabled']),('closed','confirmed',False))
        self.assertEqual(self.provider_client.require('credential.get',{'credential_id':data['credential_id']})['data']['state'],'revoked')

    def test_no_password_authentication_path_fails_closed_and_disables_login(self):
        (self.cluster.data_dir/'pg_hba.conf').write_text('local all all trust\n')
        self.cluster.psql('SELECT pg_reload_conf()')
        request=self.request()
        with self.assertRaisesRegex(CredentialError,'incorrect password'): self.broker.issue_request(request)
        data=self.bridge.data(request)
        self.assertFalse(data['login_enabled'])
        self.assertEqual(data['state'],'closed')
        self.assertIsNone(data['authenticated_at'])

    def test_wrong_password_probe_transport_outage_is_not_password_denial(self):
        execute=PsqlTransport.execute_sql
        def fault(transport,sql,**kwargs):
            if transport.connection.user.startswith('hbx_') and sql=='SELECT session_user;':
                raise TransportError('controlled transport outage before password response')
            return execute(transport,sql,**kwargs)
        request=self.request()
        with patch.object(PsqlTransport,'execute_sql',fault):
            with self.assertRaises(CredentialError): self.broker.issue_request(request)
        data=self.bridge.data(request)
        self.assertIsNone(data['authenticated_at'])
        self.assertFalse(data['login_enabled'])
        self.assertIsNone(data['credential_id'])

    def test_wrong_database_cannot_activate_or_authenticate_a_witness(self):
        wrong_admin=PsqlTransport(replace(self.connection,database='postgres'),psql=self.admin_transport.psql)
        wrong_bridge=PostgresExternalBridge(wrong_admin,self.provider_client)
        # The real helper inventory is absent in this other database. Refusal
        # precedes HTTP issuance and no role has been created for this request.
        with self.assertRaises((CredentialError,TransportError)):
            CredentialBroker(self.provider_client,self.new_provider(wrong_bridge)).issue_request(self.request())
        self.assertEqual(self.calls,[])

    def test_renew_hook_requires_approved_pending_extension_and_bounds_actual_expiry(self):
        lease=self.issue()
        command=f"SELECT hobnail_external.renew_role('worker-basic','{lease.login}',clock_timestamp()+interval '1 day')"
        with self.assertRaises(TransportError): self.issuer_transport.execute_sql(command)
        self.assertEqual(self.bridge.data(lease.request_id)['expires_at'],lease.expires_at)
        self.worker.require('credential.renew_requested',{'credential_id':lease.credential_id,'ttl_seconds':20})
        actual=json.loads(self.issuer_transport.execute_sql(command))
        remaining=float(self.admin_transport.execute_sql(
            f"SELECT extract(epoch FROM rolvaliduntil-clock_timestamp()) FROM pg_roles WHERE rolname='{lease.login}'"))
        self.assertGreater(remaining,0); self.assertLessEqual(remaining,20)
        self.provider_client.require('credential.renewed',{'credential_id':lease.credential_id,'expires_at':actual['expires_at']})
        with self.assertRaises(TransportError): self.issuer_transport.execute_sql(command)

    def test_creation_witness_is_immutable_and_closed_bound_attempt_requires_kernel_revocation(self):
        lease=self.issue()
        with self.assertRaises(TransportError):
            self.admin_transport.execute_sql('UPDATE hobnail.external_creations SET created_at=clock_timestamp()')
        self.bridge.revoke_local(lease.request_id)
        with self.assertRaises(Denied): self.bridge.close(lease.request_id,'confirmed')
        self.assertEqual(self.provider_client.require('credential.get',{'credential_id':lease.credential_id})['data']['state'],'active')
        self.assertEqual(self.broker.reconcile_request(lease.request_id).result,'confirmed')
        self.assertEqual(self.bridge.data(lease.request_id)['state'],'closed')

    def test_completed_revocation_survives_restart_without_new_http_authority(self):
        lease=self.issue()
        self.worker.require('credential.revoke_requested',{'credential_id':lease.credential_id})
        self.assertEqual(self.broker.revoke_requested(lease.credential_id).result,'confirmed')
        calls=len(self.calls)
        restarted=CredentialBroker(self.provider_client,self.new_provider())
        self.assertEqual(restarted.reconcile_request(lease.request_id).result,'confirmed')
        self.assertEqual(len(self.calls),calls)

    def test_revoke_http_failure_stays_pending_even_after_database_denial(self):
        lease=self.issue(); self.mode='revoke_unavailable'
        self.worker.require('credential.revoke_requested',{'credential_id':lease.credential_id})
        observed=self.broker.revoke_requested(lease.credential_id)
        self.assertEqual(observed.result,'pending'); self.assertFalse(observed.login_enabled)
        self.assertEqual(self.provider_client.require('credential.get',{'credential_id':lease.credential_id})['data']['state'],'revocation_pending')
        self.mode='normal'
        self.assertEqual(self.broker.revoke_requested(lease.credential_id).result,'confirmed')

    def test_queued_provider_revocation_does_not_claim_confirmation(self):
        lease=self.issue(); self.mode='revoke_queued'
        self.worker.require('credential.revoke_requested',{'credential_id':lease.credential_id})
        result=self.broker.revoke_requested(lease.credential_id)
        self.assertEqual(result.result,'pending')
        self.assertFalse(result.login_enabled)
        self.assertEqual(self.provider_client.require('credential.get',{'credential_id':lease.credential_id})['data']['state'],'revocation_pending')

    def test_revocation_terminates_an_actual_existing_session(self):
        lease=self.issue()
        env={'LC_ALL':'C','PGPASSFILE':os.devnull,'PGSERVICEFILE':os.devnull,'PGSYSCONFDIR':str(self.cluster.root),
             'PGPASSWORD':lease.password.reveal()}
        process=subprocess.Popen([str(self.cluster.bin_dir/'psql'),'-X','-w','-h',str(self.cluster.socket_dir),
            '-p',str(self.cluster.port),'-U',lease.login,'-d',self.cluster.database,'-c','SELECT pg_sleep(30)'],
            env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            for _ in range(100):
                if self.bridge.data(lease.request_id)['active_sessions']==1: break
                time.sleep(.01)
            else: self.fail('active session never observed')
            self.worker.require('credential.revoke_requested',{'credential_id':lease.credential_id})
            observed=self.broker.revoke_requested(lease.credential_id)
            self.assertEqual((observed.result,observed.active_sessions),('confirmed',0))
            process.communicate(timeout=5); self.assertNotEqual(process.returncode,0)
        finally:
            if process.poll() is None: process.terminate(); process.communicate(timeout=5)


if __name__=='__main__': unittest.main()
