package io.github.vvb2060.keyattestation.home

import android.app.Dialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Bundle
import android.text.method.LinkMovementMethod
import android.view.LayoutInflater
import android.view.Menu
import android.view.MenuInflater
import android.view.MenuItem
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts.CreateDocument
import androidx.activity.result.contract.ActivityResultContracts.GetContent
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.widget.AppCompatEditText
import androidx.core.view.MenuProvider
import androidx.core.view.isVisible
import com.google.common.io.BaseEncoding
import androidx.fragment.app.viewModels
import androidx.recyclerview.widget.LinearLayoutManager
import io.github.vvb2060.keyattestation.AppApplication
import io.github.vvb2060.keyattestation.BuildConfig
import io.github.vvb2060.keyattestation.R
import io.github.vvb2060.keyattestation.app.AlertDialogFragment
import io.github.vvb2060.keyattestation.app.AppFragment
import io.github.vvb2060.keyattestation.attestation.Attestation
import io.github.vvb2060.keyattestation.attestation.AuthorizationList
import io.github.vvb2060.keyattestation.databinding.HomeBinding
import io.github.vvb2060.keyattestation.keystore.KeyStoreManager
import io.github.vvb2060.keyattestation.lang.AttestationException
import io.github.vvb2060.keyattestation.repository.AttestationData
import io.github.vvb2060.keyattestation.util.Status
import rikka.html.text.HtmlCompat
import rikka.html.text.toHtml
import rikka.shizuku.Shizuku
import rikka.widget.borderview.BorderView

class HomeFragment : AppFragment(), HomeAdapter.Listener, MenuProvider {

    private var _binding: HomeBinding? = null

    private val binding: HomeBinding get() = _binding!!

    private val viewModel: HomeViewModel by viewModels { HomeViewModel.Factory }

    private val save = registerForActivityResult(CreateDocument("application/x-pkcs7-certificates")) {
        viewModel.save(it)
    }

    private val load = registerForActivityResult(GetContent()) {
        viewModel.load(it)
    }

    private val import = registerForActivityResult(GetContent()) {
        viewModel.import(it)
    }

    private val adapter by lazy {
        HomeAdapter(this)
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        _binding = HomeBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        requireActivity().addMenuProvider(this, viewLifecycleOwner)

        val context = view.context

        binding.list.borderVisibilityChangedListener = BorderView.OnBorderVisibilityChangedListener { top: Boolean, _: Boolean, _: Boolean, _: Boolean -> appActivity?.appBar?.setRaised(!top) }
        binding.list.layoutManager = LinearLayoutManager(context)
        binding.list.adapter = adapter
        binding.list.addItemDecoration(HomeItemDecoration(context))

        viewModel.getAttestationData().observe(viewLifecycleOwner) { res ->
            when (res.status) {
                Status.SUCCESS -> {
                    binding.progress.isVisible = false
                    binding.list.isVisible = true
                    adapter.updateData(res.data!!)
                }
                Status.ERROR -> {
                    binding.progress.isVisible = false
                    binding.list.isVisible = true
                    adapter.updateData(res.error as AttestationException)
                }
                Status.LOADING -> {
                    binding.progress.isVisible = true
                    binding.list.isVisible = false
                }
            }
        }
    }

    override fun onAttestationInfoClick(data: Attestation) {
        val result = viewModel.getAttestationData().value!!.data!! as AttestationData
        result.showAttestation = data
        adapter.updateData(result)
    }

    override fun onRkpHostnameClick(data: String) {
        val context = requireContext()
        val dp24 = Math.round(24 * context.resources.displayMetrics.density)
        val dp18 = Math.round(18 * context.resources.displayMetrics.density)
        val editText = AppCompatEditText(context)
        editText.setHint(R.string.rkp_hostname_empty)
        editText.setText(data)
        editText.setPadding(dp24, dp18, dp24, dp18)
        editText.requestFocus()

        AlertDialog.Builder(context)
            .setView(editText)
            .setTitle(R.string.rkp_hostname)
            .setPositiveButton(android.R.string.ok) { _, _ ->
                viewModel.rkp(editText.text?.toString())
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    override fun onCommonDataClick(data: Data) {
        val context = requireActivity()

        AlertDialogFragment.Builder(context)
            .title(data.title)
            .message(data.getMessage(context))
            .positiveButton(android.R.string.ok)
            .build()
            .show(context.supportFragmentManager)
    }

    override fun onPrepareMenu(menu: Menu) {
        menu.findItem(R.id.menu_use_shizuku).apply {
            isVisible = Shizuku.pingBinder()
            val received = KeyStoreManager.getRemoteKeyStore() != null
            if (!received) viewModel.preferShizuku = false
            isEnabled = received
            isChecked = viewModel.preferShizuku
        }

        menu.findItem(R.id.menu_secret_mode).apply {
            isVisible = true
            isChecked = viewModel.secretMode
        }

        menu.findItem(R.id.menu_use_strongbox)?.isVisible = !viewModel.preferSak
        menu.findItem(R.id.menu_use_attest_key)?.isVisible = !viewModel.preferSak
        menu.findItem(R.id.menu_import_attest_key)?.isVisible = !viewModel.preferSak
                && viewModel.preferAttestKey

        menu.setGroupVisible(R.id.menu_id_type_group, viewModel.preferShizuku)
        menu.findItem(R.id.menu_include_unique_id).isVisible =
            viewModel.preferShizuku && viewModel.canIncludeUniqueId
        menu.findItem(R.id.menu_rkp_test).isVisible =
            viewModel.preferShizuku && viewModel.canCheckRkp
        menu.findItem(R.id.menu_use_sak)?.isVisible =
            viewModel.preferShizuku && viewModel.canSak

        menu.findItem(R.id.menu_save).isVisible = viewModel.hasCertificates()
    }

    override fun onCreateMenu(menu: Menu, menuInflater: MenuInflater) {
        menuInflater.inflate(R.menu.home, menu)
        menu.findItem(R.id.menu_use_strongbox).isChecked = viewModel.preferStrongBox
        menu.findItem(R.id.menu_use_attest_key).isChecked = viewModel.preferAttestKey
        menu.findItem(R.id.menu_include_props).isChecked = viewModel.preferIncludeProps
        menu.findItem(R.id.menu_id_type_serial).isChecked = viewModel.preferIdAttestationSerial
        menu.findItem(R.id.menu_id_type_imei).isChecked = viewModel.preferIdAttestationIMEI
        menu.findItem(R.id.menu_id_type_meid).isChecked = viewModel.preferIdAttestationMEID
        menu.findItem(R.id.menu_include_unique_id).isChecked = viewModel.preferIncludeUniqueId
        menu.findItem(R.id.menu_use_sak).isChecked = viewModel.preferSak
        if (!viewModel.hasSak) {
            menu.removeItem(R.id.menu_use_sak)
        }
        if (!viewModel.hasStrongBox) {
            menu.removeItem(R.id.menu_use_strongbox)
        }
        if (!viewModel.hasAttestKey) {
            menu.removeItem(R.id.menu_use_attest_key)
            menu.removeItem(R.id.menu_import_attest_key)
        }
        if (!viewModel.hasDeviceIds) {
            menu.removeItem(R.id.menu_include_props)
            menu.removeItem(R.id.menu_id_type_serial)
            menu.removeItem(R.id.menu_id_type_imei)
            menu.removeItem(R.id.menu_id_type_meid)
        }
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            menu.removeItem(R.id.menu_include_props)
        }
        if (!viewModel.hasIMEI) {
            menu.removeItem(R.id.menu_id_type_imei)
        }
        if (!viewModel.hasMEID) {
            menu.removeItem(R.id.menu_id_type_meid)
        }
    }

    override fun onMenuItemSelected(item: MenuItem): Boolean {
        val status = !item.isChecked
        item.isChecked = status
        when (item.itemId) {
            R.id.menu_secret_mode -> {
                viewModel.secretMode = status
                viewModel.load()
            }
            R.id.menu_use_shizuku -> {
                viewModel.preferShizuku = status
                viewModel.load()
            }
            R.id.menu_use_sak -> {
                viewModel.preferSak = status
                viewModel.load()
            }
            R.id.menu_use_strongbox -> {
                viewModel.preferStrongBox = status
                viewModel.load()
            }
            R.id.menu_use_attest_key -> {
                viewModel.preferAttestKey = status
                viewModel.load()
            }
            R.id.menu_include_props -> {
                viewModel.preferIncludeProps = status
                viewModel.load()
            }
            R.id.menu_id_type_serial -> {
                viewModel.preferIdAttestationSerial = status
                viewModel.load()
            }
            R.id.menu_id_type_imei -> {
                viewModel.preferIdAttestationIMEI = status
                viewModel.load()
            }
            R.id.menu_id_type_meid -> {
                viewModel.preferIdAttestationMEID = status
                viewModel.load()
            }
            R.id.menu_include_unique_id -> {
                viewModel.preferIncludeUniqueId = status
                viewModel.load()
            }
            R.id.menu_copy_vbhash -> {
                val context = requireContext()
                copyVerifiedBootHash(context)
            }
            R.id.menu_rkp_test -> {
                viewModel.rkp()
            }
            R.id.menu_reset -> {
                viewModel.load(true)
            }
            R.id.menu_save -> {
                save.launch("${Build.PRODUCT}-${AppApplication.TAG}.p7b")
            }
            R.id.menu_load -> {
                load.launch("*/*")
            }
            R.id.menu_import_attest_key -> {
                import.launch("text/xml")
            }
            R.id.menu_about -> {
                showAboutDialog()
            }
            else -> return false
        }
        return true
    }

    private fun showAboutDialog() {
        val context = requireContext()
        val text = StringBuilder()
        val source = "<b><a href=\"${context.getString(R.string.github_url)}\">GitHub</a></b>"
        val shizuku = "<b><a href=\"${context.getString(R.string.shizuku_url)}\">Web</a></b>"
        text.append(BuildConfig.VERSION_NAME).append("<p>")
        text.append(getString(R.string.open_source_info, source, context.getString(R.string.license)))
        if (Shizuku.pingBinder()) {
            KeyStoreManager.requestPermission()
        } else if (KeyStoreManager.isShizukuInstalled()) {
            KeyStoreManager.requestBinder(context)
            text.append("<p>").append(context.getString(R.string.start_shizuku))
        } else {
            text.append("<p>").append(context.getString(R.string.install_shizuku, shizuku))
        }
        text.append("<p>").append(context.getString(R.string.copyright))
        val icon = context.getDrawable(R.drawable.ic_launcher)
        val dialog: Dialog = AlertDialog.Builder(context)
                .setView(rikka.material.R.layout.dialog_about)
                .show()
        dialog.findViewById<TextView>(rikka.material.R.id.design_about_info).isVisible = false
        dialog.findViewById<ImageView>(rikka.material.R.id.design_about_icon).setImageDrawable(icon)
        dialog.findViewById<TextView>(rikka.material.R.id.design_about_title).text = getString(R.string.app_name)
        dialog.findViewById<TextView>(rikka.material.R.id.design_about_version).apply {
            movementMethod = LinkMovementMethod.getInstance()
            this.text = text.toHtml(HtmlCompat.FROM_HTML_OPTION_TRIM_WHITESPACE)
        }

    }

    private fun copyVerifiedBootHash(context: Context) {
        when (viewModel.getAttestationData().value?.status) {
            Status.SUCCESS -> {
                val rootOfTrust = (viewModel.getAttestationData().value!!.data as AttestationData).rootOfTrust
                val verifiedBootHash = BaseEncoding.base16().encode(rootOfTrust.verifiedBootHash).lowercase()
                val clipboardManager =
                    context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                clipboardManager.setPrimaryClip(ClipData.newPlainText("hash", verifiedBootHash))
                if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.S_V2)
                    Toast.makeText(context, R.string.copy_vbhash_success, Toast.LENGTH_SHORT).show()
            }

            Status.ERROR -> {
                Toast.makeText(context, R.string.copy_vbhash_error, Toast.LENGTH_SHORT).show()
            }

            Status.LOADING, null -> {
                Toast.makeText(context, R.string.copy_vbhash_loading, Toast.LENGTH_SHORT).show()
            }
        }
    }

}
