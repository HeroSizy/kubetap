// Copyright 2020 Soluble Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	k8sappsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/utils/pointer"
)

var (
	// data volume names much have a "kubetap" prefix to be
	// properly removed during untapping.
	mitmproxyDataVolName = "kubetap-mitmproxy-data"
	mitmproxySslVolName  = "kubetap-mitmproxy-ssl"

	mitmproxyConfigFile = "config.yaml"
	mitmproxyBaseConfig = `listen_port: 7777
ssl_insecure: true
web_port: 2244
web_host: 0.0.0.0
web_open_browser: false
`
)

// MitmproxySidecarContainer is the default proxy sidecar for HTTP Taps.
var MitmproxySidecarContainer = v1.Container{
	Name: kubetapContainerName,
	// Image:           image,       // Image is controlled by main
	// Args:            commandArgs, // Args is controlled by main
	ImagePullPolicy: v1.PullAlways,
	Ports: []v1.ContainerPort{
		{
			Name:          kubetapPortName,
			ContainerPort: kubetapProxyListenPort,
			Protocol:      v1.ProtocolTCP,
		},
		{
			Name:          kubetapWebPortName,
			ContainerPort: kubetapProxyWebInterfacePort,
			Protocol:      v1.ProtocolTCP,
		},
	},
	SecurityContext: &v1.SecurityContext{
		Capabilities: &v1.Capabilities{
			Drop: []v1.Capability{
				v1.Capability("ALL"),
			},
		},
		Privileged:               pointer.Bool(false),
		RunAsUser:                pointer.Int64(10001),
		RunAsGroup:               pointer.Int64(10001),
		RunAsNonRoot:             pointer.Bool(true),
		AllowPrivilegeEscalation: pointer.Bool(false),
		SeccompProfile: &v1.SeccompProfile{
			Type: v1.SeccompProfileTypeRuntimeDefault,
		},
	},
	Resources: v1.ResourceRequirements{
		Limits: v1.ResourceList{
			v1.ResourceCPU:    resource.MustParse("100m"),
			v1.ResourceMemory: resource.MustParse("64Mi"),
		},
		Requests: v1.ResourceList{
			v1.ResourceCPU:    resource.MustParse("100m"),
			v1.ResourceMemory: resource.MustParse("64Mi"),
		},
	},
	ReadinessProbe: &v1.Probe{
		InitialDelaySeconds: 2,
		PeriodSeconds:       2,
		SuccessThreshold:    1,
		TimeoutSeconds:      1,
		ProbeHandler: v1.ProbeHandler{
			HTTPGet: &v1.HTTPGetAction{
				Path:   "/",
				Port:   intstr.FromInt(kubetapProxyWebInterfacePort),
				Scheme: v1.URISchemeHTTP,
			},
		},
	},
	VolumeMounts: []v1.VolumeMount{
		{
			// Name:    "", // Name is controlled by main
			MountPath: "/home/mitmproxy/config/",
			// We store outside main dir to prevent RO problems, see below.
			// This also means that we need to wrap the official mitmproxy container.
			/*
				// *sigh* https://github.com/kubernetes/kubernetes/issues/64120
				ReadOnly: false, // mitmproxy container does a chown
				MountPath: "/home/mitmproxy/.mitmproxy/config.yaml",
				SubPath:   "config.yaml", // we only mount the config file
			*/
		},
		{
			Name:      mitmproxyDataVolName,
			MountPath: "/home/mitmproxy/.mitmproxy",
			ReadOnly:  false,
		},
	},
}

const (
	ModeReverse = "reverse"
)

// NewMitmproxy initializes a new mitmproxy Tap.
func NewMitmproxy(c kubernetes.Interface, p ProxyOptions, mode string) Tap {
	// mitmproxy only supports one mode right now.
	// How we expose options for other modes may
	// be explored in the future.
	p.Mode = mode
	return &Mitmproxy{
		Protos:    []Protocol{protocolHTTP},
		Client:    c,
		ProxyOpts: p,
	}
}

// Mitmproxy is a interactive web proxy for intercepting and modifying HTTP requests.
type Mitmproxy struct {
	Protos    []Protocol
	Client    kubernetes.Interface
	ProxyOpts ProxyOptions
}

// Sidecar provides a proxy sidecar container.
func (m *Mitmproxy) Sidecar(deploymentName string) v1.Container {
	c := MitmproxySidecarContainer
	c.VolumeMounts[0].Name = kubetapConfigMapPrefix + deploymentName
	return c
}

// PatchDeployment provides any necessary tweaks to the deployment after the sidecar is added.
func (m *Mitmproxy) PatchDeployment(deployment *k8sappsv1.Deployment) {
	deployment.Spec.Template.Spec.Volumes = append(deployment.Spec.Template.Spec.Volumes, v1.Volume{
		Name: kubetapConfigMapPrefix + deployment.Name,
		VolumeSource: v1.VolumeSource{
			ConfigMap: &v1.ConfigMapVolumeSource{
				LocalObjectReference: v1.LocalObjectReference{
					Name: kubetapConfigMapPrefix + deployment.Name,
				},
			},
		},
	})

	// add emptydir to resolve permission problems, and to down the road export dumps
	deployment.Spec.Template.Spec.Volumes = append(deployment.Spec.Template.Spec.Volumes, v1.Volume{
		Name: mitmproxyDataVolName,
		VolumeSource: v1.VolumeSource{
			EmptyDir: &v1.EmptyDirVolumeSource{},
		},
	})

	deployment.Spec.Template.Spec.Volumes = append(deployment.Spec.Template.Spec.Volumes, v1.Volume{
		Name: mitmproxySslVolName,
		VolumeSource: v1.VolumeSource{
			EmptyDir: &v1.EmptyDirVolumeSource{},
		},
	})

	// patch the mitmproxy container to use the proxy
	for i := range deployment.Spec.Template.Spec.Containers {
		if strings.HasPrefix(deployment.Spec.Template.Spec.Containers[i].Name, "kubetap") {
			continue
		}

		deployment.Spec.Template.Spec.Containers[i].VolumeMounts = append(deployment.Spec.Template.Spec.Containers[i].VolumeMounts, v1.VolumeMount{
			Name:      mitmproxyDataVolName,
			MountPath: "/tmp/mitmproxy",
		})

		deployment.Spec.Template.Spec.Containers[i].VolumeMounts = append(deployment.Spec.Template.Spec.Containers[i].VolumeMounts, v1.VolumeMount{
			Name:      mitmproxySslVolName,
			MountPath: "/etc/ssl/certs",
		})

		// deployment.Spec.Template.Spec.Containers[i].SecurityContext.ReadOnlyRootFilesystem = pointer.Bool(false)
		//
		// deployment.Spec.Template.Spec.Containers[i].Resources = v1.ResourceRequirements{
		// 	Limits: v1.ResourceList{
		// 		v1.ResourceCPU:    resource.MustParse("100m"),
		// 		v1.ResourceMemory: resource.MustParse("64Mi"),
		// 	},
		// 	Requests: v1.ResourceList{
		// 		v1.ResourceCPU:    resource.MustParse("100m"),
		// 		v1.ResourceMemory: resource.MustParse("64Mi"),
		// 	},
		// }

		deployment.Spec.Template.Spec.Containers[i].Env = append(
			deployment.Spec.Template.Spec.Containers[i].Env,
			v1.EnvVar{
				Name:  "http_proxy",
				Value: "http://localhost:7777",
			},
			v1.EnvVar{
				Name:  "https_proxy",
				Value: "http://localhost:7777",
			})

		deployment.Spec.Template.Spec.Containers[i].Lifecycle = &v1.Lifecycle{
			PostStart: &v1.LifecycleHandler{
				Exec: &v1.ExecAction{
					Command: []string{
						"update-ca-certificates",
					},
				},
			},
		}
	}
}

func (m *Mitmproxy) UnPatchDeployment(deployment *k8sappsv1.Deployment) {
	for i := range deployment.Spec.Template.Spec.Containers {
		if deployment.Spec.Template.Spec.Containers[i].Name == kubetapContainerName {
			continue
		}

		var envs []v1.EnvVar
		for j := range deployment.Spec.Template.Spec.Containers[i].Env {
			if !strings.HasSuffix(deployment.Spec.Template.Spec.Containers[i].Env[j].Name, "_proxy") {
				envs = append(envs, deployment.Spec.Template.Spec.Containers[i].Env[j])
			}
		}
		deployment.Spec.Template.Spec.Containers[i].Env = envs

		var mounts []v1.VolumeMount
		for j := range deployment.Spec.Template.Spec.Containers[i].VolumeMounts {

			if strings.HasPrefix(deployment.Spec.Template.Spec.Containers[i].VolumeMounts[j].Name, "kubetap") {
				continue
			}

			mounts = append(mounts, deployment.Spec.Template.Spec.Containers[i].VolumeMounts[j])
		}
		deployment.Spec.Template.Spec.Containers[i].VolumeMounts = mounts
		deployment.Spec.Template.Spec.Containers[i].Lifecycle = nil
	}

	var volumes []v1.Volume

	for i := range deployment.Spec.Template.Spec.Volumes {
		if strings.HasPrefix(deployment.Spec.Template.Spec.Volumes[i].Name, "kubetap") {
			continue
		}

		volumes = append(volumes, deployment.Spec.Template.Spec.Volumes[i])
	}
	deployment.Spec.Template.Spec.Volumes = volumes
}

// Protocols returns a slice of protocols supported by Mitmproxy, currently only HTTP.
func (m *Mitmproxy) Protocols() []Protocol {
	return m.Protos
}

// String is called to conveniently print the type of Tap to stdout.
func (m *Mitmproxy) String() string {
	return "mitmproxy"
}

// ReadyEnv readies the environment by providing a ConfigMap for the mitmproxy container.
func (m *Mitmproxy) ReadyEnv() error {
	configmapsClient := m.Client.CoreV1().ConfigMaps(m.ProxyOpts.Namespace)
	// Create the ConfigMap based the options we're configuring mitmproxy with
	if err := createMitmproxyConfigMap(configmapsClient, m.ProxyOpts); err != nil {
		// If the service hasn't been tapped but still has a configmap from a previous
		// run (which can happen if the deployment borks and "tap off" isn't explicitly run,
		// delete the configmap and try again.
		// This is mostly here to fix development environments that become broken during
		// code testing.
		_ = destroyMitmproxyConfigMap(configmapsClient, m.ProxyOpts.dplName)
		rErr := createMitmproxyConfigMap(configmapsClient, m.ProxyOpts)
		if rErr != nil {
			if errors.Is(os.ErrInvalid, rErr) {
				return fmt.Errorf("there was an unexpected problem creating the ConfigMap")
			}
			return rErr
		}
	}

	if err := createCertSecret(m.Client.CoreV1().Secrets(m.ProxyOpts.Namespace), m.ProxyOpts); err != nil {
		_ = destroyCertSecret(m.Client.CoreV1().Secrets(m.ProxyOpts.Namespace), m.ProxyOpts.dplName)
		rErr := createCertSecret(m.Client.CoreV1().Secrets(m.ProxyOpts.Namespace), m.ProxyOpts)
		if rErr != nil {
			if errors.Is(os.ErrInvalid, rErr) {
				return fmt.Errorf("there was an unexpected problem creating the Secret")
			}
			return rErr
		}
	}

	return nil
}

// UnreadyEnv removes tap supporting configmap.
func (m *Mitmproxy) UnreadyEnv() error {
	configmapsClient := m.Client.CoreV1().ConfigMaps(m.ProxyOpts.Namespace)

	secretClient := m.Client.CoreV1().Secrets(m.ProxyOpts.Namespace)

	if err := destroyCertSecret(secretClient, m.ProxyOpts.dplName); err != nil {
		return err
	}

	return destroyMitmproxyConfigMap(configmapsClient, m.ProxyOpts.dplName)
}

// createMitmproxyConfigMap creates a mitmproxy configmap based on the proxy mode, however currently
// only "reverse" mode is supported.
func createMitmproxyConfigMap(configmapClient corev1.ConfigMapInterface, proxyOpts ProxyOptions) error {
	// TODO: eventually, we should build a struct and use yaml to marshal this,
	// but for now we're just doing string concatenation.
	var mitmproxyConfig []byte
	switch proxyOpts.Mode {
	case "reverse":
		if proxyOpts.UpstreamHTTPS {
			mitmproxyConfig = append([]byte(mitmproxyBaseConfig), []byte("mode: [regular, reverse:https://127.0.0.1:"+proxyOpts.UpstreamPort+"@7776]")...)
		} else {
			mitmproxyConfig = append([]byte(mitmproxyBaseConfig), []byte("mode: [regular, reverse:http://127.0.0.1:"+proxyOpts.UpstreamPort+"@7776]")...)
		}
	case "regular":
		// non-applicable
		// return errors.New("mitmproxy container only supports \"reverse\" mode")
	case "socks5":
		// non-applicable
		return errors.New("mitmproxy container only supports \"reverse\" mode")
	case "upstream":
		// non-applicable, unless you really know what you're doing, in which case fork this and connect it to your existing proxy
		return errors.New("mitmproxy container only supports \"reverse\" mode")
	case "transparent":
		// Because transparent mode uses iptables, it's not supported as we cannot guarantee that iptables is available and functioning
		return errors.New("mitmproxy container only supports \"reverse\" mode")
	default:
		return errors.New("invalid proxy mode: \"" + proxyOpts.Mode + "\"")
	}
	cmData := make(map[string][]byte)
	cmData[mitmproxyConfigFile] = mitmproxyConfig
	cm := v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      kubetapConfigMapPrefix + proxyOpts.dplName,
			Namespace: proxyOpts.Namespace,
			Annotations: map[string]string{
				annotationConfigMap: configMapAnnotationPrefix + proxyOpts.dplName,
			},
		},
		BinaryData: cmData,
	}
	slen := len(cm.BinaryData[mitmproxyConfigFile])
	if slen == 0 {
		return os.ErrInvalid
	}
	ccm, err := configmapClient.Create(context.TODO(), &cm, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	if ccm.BinaryData == nil {
		return os.ErrInvalid
	}
	cdata := ccm.BinaryData[mitmproxyConfigFile]
	if len(cdata) != slen {
		return ErrCreateResourceMismatch
	}
	return nil
}

// destroyMitmproxyConfigMap removes a mitmproxy ConfigMap from the environment.
func destroyMitmproxyConfigMap(configmapClient corev1.ConfigMapInterface, deploymentName string) error {
	if deploymentName == "" {
		return os.ErrInvalid
	}
	cms, err := configmapClient.List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error getting ConfigMaps: %w", err)
	}
	var targetConfigMapNames []string
	for _, cm := range cms.Items {
		anns := cm.GetAnnotations()
		if anns == nil {
			continue
		}
		for k, v := range anns {
			if k == annotationConfigMap && v == configMapAnnotationPrefix+deploymentName {
				targetConfigMapNames = append(targetConfigMapNames, cm.Name)
			}
		}
	}
	if len(targetConfigMapNames) == 0 {
		return ErrConfigMapNoMatch
	}

	for _, cmName := range targetConfigMapNames {
		if err = configmapClient.Delete(context.TODO(), cmName, metav1.DeleteOptions{}); err != nil {
			return err
		}
	}

	return nil
}

func createCertSecret(secretClient corev1.SecretInterface, proxyOpts ProxyOptions) error {
	cert := "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC86PE+uF+90cS+\nTs9Z0ecAP2uNn2FXHbNrIduZYeLKZnRLVjkVihZtc5uvq0iPOwFSL3eWX0uYlAD2\n9xq1HElbkXhS5/RioKzAiypRmsSl5UnrTM/P8qf7yCr5FqqxMngG2mKVRXyCRj7d\nKo0JBm/j8ozAGlMs5YtkRPkMmpWgf8JyVG/Bg/+u5jSzZO36oJFoOx+1fk/DlO/l\najSkOJPjCVbTyDMXrbTg4ofY+Z0H+dsZSKEZoY9w+80h6e+l/3H/UdE4zBpBpqBh\nhzucL/Lpb1ZYudDYedFV3u7ieyRGbFCsrubU+6SZuTC+h1fjtFCGQw9VrZObErhz\nx95lx5exAgMBAAECggEAAVibl3nS3NRo1X5UReyT+9F337t6AxfoFmRYX0BuUEjo\nnTzRDVE9lawUOO08iCDAgqhp7r1hGYY8d4YNP6si7q8br2ONv0Ir2Pdk5s32hsQa\ngb27YVz2S3oCrGG396lHZ60YtL2ZBIihnAvYk27jTzmEPT4yx4gfNSi0qZ1UYZ9k\nSB2fpi9u9S1bZuYjJ38Vy+0I/1af14k6NQ2/326NYcnPIrZSzXP8Gizlo6YTBljW\nkSWeq6LOZK0DLpMCFlwd+Bo0avspj7ULIGq/OzPiXF6A45mX9QoB449sTHGQoHfr\nDPdYL6IXo9QZ41Xcsrs3iKUgltb2nYhKJCPa9OLnHQKBgQD4LcCm1Y8S0Otu1JvW\nhdPjCmFuQ4zX/z7DJneLSItvh4GuMlEwtJrcYYc4ykp8zZ2vxKC12ivL5EXpSNub\nkAD0TIXLW0jPt3xgE+x9aILwBJbv0XUaZClCLIQo/CSYP2WLNMcMJ1i0VBJrC8qc\nHimhEIi0K27WQpxyEYbJGHh/CwKBgQDC3QXvZifT3UJEXAXpD82d6kbSreb0Habl\n4Gkb1Ar7mwOWzZ2l3fuEicXB4D7tkH/ZHKOiMyOFV1COAp0KbZdAuuyg5fc1O3Gb\nDHC52BEE8p/L4ozEXDbVkMohhNY7+ZJFzk0vHDdYeDnXACrmNFIT2jsMyxtoGx4y\nae5BTEopswKBgQC0MIvi1cWWdMerZYRsQihwfNX2t+bn4LPR/vjm0NokNO+L6Y6X\nXVnezpTeP8nLSYLG3m2M+4W2+NtloHeKQAjhVzoBRxrbba5JF84p05rV548rOhna\n+oQWProKA+ASBl2Ur9IhWeQGsc/ZlusZZLD290k5/xrvR9fM3jrNgQ3jtwKBgQCU\nGIa6O1lpm28RpR6Y0nni2nqZA7HTNfXyH2vCypTORDGmGv8FYIAXat3xSwyIYJnJ\n2ApE67jDTmjahQH1OvUJLQdKAXyv6E2fGQVTOPM2X28y9Ssm0S6bgT8d2mc3jaWt\nh+0BMOCfTEApNudjrb/zdpgKURKzPGjmx7tbxS9YIQKBgEeSdjr76dj0ZhoghsBZ\n3oa3aBgW1moF4zcqAjhy+K2Scs7WgfJk12BWl2hDjI6JscnfznvILvrm5+90K6Cj\nLzurP7eYW7QO9ncVWYH0rfhmrIwCtCG/APvnUQO+RpZSOx5JGBQX7YHURj9sAssc\n/a3c+IoO9VXIR0yrnz9MRaRu\n-----END PRIVATE KEY-----\n-----BEGIN CERTIFICATE-----\nMIIDazCCAlOgAwIBAgIUMleeBOrTuqCtA4EaYyc2/+MjG5gwDQYJKoZIhvcNAQEL\nBQAwRTELMAkGA1UEBhMCU0cxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM\nGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yNDAxMTgxMTA2MTRaFw0yNDAy\nMTcxMTA2MTRaMEUxCzAJBgNVBAYTAlNHMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw\nHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB\nAQUAA4IBDwAwggEKAoIBAQC86PE+uF+90cS+Ts9Z0ecAP2uNn2FXHbNrIduZYeLK\nZnRLVjkVihZtc5uvq0iPOwFSL3eWX0uYlAD29xq1HElbkXhS5/RioKzAiypRmsSl\n5UnrTM/P8qf7yCr5FqqxMngG2mKVRXyCRj7dKo0JBm/j8ozAGlMs5YtkRPkMmpWg\nf8JyVG/Bg/+u5jSzZO36oJFoOx+1fk/DlO/lajSkOJPjCVbTyDMXrbTg4ofY+Z0H\n+dsZSKEZoY9w+80h6e+l/3H/UdE4zBpBpqBhhzucL/Lpb1ZYudDYedFV3u7ieyRG\nbFCsrubU+6SZuTC+h1fjtFCGQw9VrZObErhzx95lx5exAgMBAAGjUzBRMB0GA1Ud\nDgQWBBQvmIrRlvTJNFAS4mrPd7tCnAzMPzAfBgNVHSMEGDAWgBQvmIrRlvTJNFAS\n4mrPd7tCnAzMPzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCu\nlZS6DRl5yqxaPizYIiOIh5te2U4pUXZPdjGNfUJG4EOcXDA8NZtwsJ6uqBv1CWR4\nolNsXaRc/N5pWcaANV4I/RqrcSpRL2ffz+hyGTU5syBI7qOP1BSizea5gK/yURbz\n+DVpcjQ9ftM6GK6eJ7cfFhCZROwIciat0SlbeWMUFltkXWawDkyGe/sdaVATGJLr\n/KhI2AMDrPPNwj5OM0WK7Ar75x+nKx1tp0FLGLdN6KeU34qzKx7cLf854jW3TRtZ\nfMKqwdPG6UAeaUlaaXZeXuHssEiJHGYMOJobxzQnl7Fw1IWOj2M5hGRXOwJO6l7Z\nmmLRWufaz3J87PiBvd63\n-----END CERTIFICATE-----\n"

	secret := v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      kubetapConfigMapPrefix + proxyOpts.dplName,
			Namespace: proxyOpts.Namespace,
			Annotations: map[string]string{
				annotationSecret: configMapAnnotationPrefix + proxyOpts.dplName,
			},
		},
		Type: v1.SecretTypeOpaque,
		Data: map[string][]byte{
			"cert.pem": []byte(cert),
		},
	}
	_, err := secretClient.Create(context.Background(), &secret, metav1.CreateOptions{})
	return err
}

func destroyCertSecret(secretClient corev1.SecretInterface, deploymentName string) error {
	if deploymentName == "" {
		return os.ErrInvalid
	}
	secrets, err := secretClient.List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("error getting Secrets: %w", err)
	}
	var targetSecretNames []string
	for _, secret := range secrets.Items {
		anns := secret.GetAnnotations()
		if anns == nil {
			continue
		}
		for k, v := range anns {
			if k == annotationSecret && v == configMapAnnotationPrefix+deploymentName {
				targetSecretNames = append(targetSecretNames, secret.Name)
			}
		}
	}
	if len(targetSecretNames) == 0 {
		return ErrConfigMapNoMatch
	}
	return secretClient.Delete(context.Background(), targetSecretNames[0], metav1.DeleteOptions{})
}
